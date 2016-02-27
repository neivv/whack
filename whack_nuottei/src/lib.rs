#![crate_type="dylib"]
#![feature(quote, plugin_registrar, slice_patterns, rustc_private)]

extern crate nuottei;
extern crate rustc_plugin;
extern crate syntax;

use syntax::codemap::{DUMMY_SP, Span, Spanned, Pos};
use syntax::ast::{self, ExprKind, ItemKind, TokenTree, TyKind};
use syntax::ext::build::AstBuilder;
use syntax::ext::base::{ExtCtxt, MacResult, DummyResult, MacEager};
use syntax::parse::token::{self, InternedString};
use syntax::print::pprust;
use syntax::util::small_vector::SmallVector;
use syntax::fold::Folder;
use syntax::ptr::P;
use syntax::abi::Abi;
use rustc_plugin::Registry;

use std::default::Default;
use std::path::PathBuf;
use std::mem;
use std::fmt::Write;
use std::fs;
use std::io::Read;

use nuottei::{Declaration, Stack, Register};

#[plugin_registrar]
pub fn plugin_registrar(reg: &mut Registry) {
    reg.register_macro("import_nuottei", generate_from_txt);
    reg.register_macro("import_hooks", generate_hooks);
}

fn unit_ty(cx: &ExtCtxt, sp: Span) -> P<ast::Ty> {
    cx.ty(sp, TyKind::Tup(Vec::new()))
}

fn to_rust_type(cx: &ExtCtxt, sp: Span, input: &nuottei::Type, default_ty: Option<P<ast::Ty>>) -> Option<P<ast::Ty>> {
    match *input {
        nuottei::Type::Basic(name) => {
            Some(match name {
                "dword" => quote_ty!(cx, u32),
                "int" => quote_ty!(cx, i32),
                "word" => quote_ty!(cx, u16),
                "byte" => quote_ty!(cx, u8),
                "char" => quote_ty!(cx, ::std::os::raw::c_char),
                "void" => quote_ty!(cx, ::std::os::raw::c_void),
                "wchar" => quote_ty!(cx, u16),
                n => cx.ty_ident(sp, cx.ident_of(n)),
            })
        }
        nuottei::Type::Pointer(mutable, ref inner) => to_rust_type(cx, sp, inner, default_ty)
            .map(|t| cx.ty_ptr(sp, t, if mutable { ast::Mutability::Mutable } else { ast::Mutability::Immutable })),
        nuottei::Type::Array(size, ref inner) => to_rust_type(cx, sp, inner, default_ty)
            .map(|t| cx.ty(sp, TyKind::FixedLengthVec(t, cx.expr_usize(sp, size as usize)))),
        nuottei::Type::Default => default_ty,
    }
}

// Because rust does not like static sharing name
fn arg_name(arg: &nuottei::Arg) -> String {
    format!("fn_arg_{}", arg.name)
}

fn make_inputs(cx: &ExtCtxt, sp: Span, func: &nuottei::Function) -> Vec<ast::Arg> {
    let def_ty = cx.ty_ident(sp, cx.ident_of("u32"));
    func.args.iter().map(|a| {
        cx.arg(sp, cx.ident_of(&arg_name(a)), to_rust_type(cx, sp, &a.tp, Some(def_ty.clone())).unwrap())
    }).collect()
}

fn unsafe_block(sp: Span, stmts: Vec<ast::Stmt>, expr: Option<P<ast::Expr>>) -> P<ast::Block> {
    P(ast::Block {
        stmts: stmts,
        expr: expr,
        id: ast::DUMMY_NODE_ID,
        rules: ast::BlockCheckMode::Unsafe(ast::CompilerGenerated), // Not sure about CompilerGenerated
        span: sp,
    })
}

fn make_asm(cx: &ExtCtxt, sp: Span, asm: InternedString, outputs: Vec<(InternedString, P<ast::Expr>)>,
    inputs: Vec<(InternedString, P<ast::Expr>)>, clobbers: Vec<InternedString>) -> P<ast::Expr> {
    cx.expr(sp, ExprKind::InlineAsm(ast::InlineAsm {
        asm: asm,
        asm_str_style: ast::StrStyle::Cooked,
        outputs: outputs.into_iter().map(|tp| ast::InlineAsmOutput {
            constraint: tp.0,
            expr: tp.1,
            is_rw: false,
            is_indirect: false,
        }).collect(),
        inputs: inputs,
        clobbers: clobbers,
        volatile: true,
        alignstack: false,
        dialect: ast::AsmDialect::Att,
        expn_id: cx.backtrace(),
    }))
}

fn expr_transmute(cx: &ExtCtxt, sp: Span, expr: P<ast::Expr>) -> P<ast::Expr> {
    let transmute = cx.std_path(&["mem", "transmute"]);
    cx.expr_call_global(sp, transmute, vec!(expr))
}

fn expr_transmute_id(cx: &ExtCtxt, sp: Span, in_name: &str) -> P<ast::Expr> {
    expr_transmute(cx, sp, cx.expr_ident(sp, cx.ident_of(in_name)))
}

fn add_stack_args(cx: &ExtCtxt, sp: Span, func: &nuottei::Function, stmts: &mut Vec<ast::Stmt>) {
    if !func.args.iter().any(|a| a.location.stack().is_some()) {
        return;
    }
    stmts.push(quote_stmt!(cx, let stack: *mut usize;).unwrap());
    stmts.push(cx.stmt_expr(make_asm(cx, DUMMY_SP, InternedString::new(""),
        vec!((InternedString::new("={esp}"), quote_expr!(cx, stack))), vec!(), vec!())));

    let stack_size = func.args.iter().filter(|a| a.location.stack().is_some()).count();
    for arg in func.args.iter().filter(|a| a.location.stack().is_some()) {
        let pos = arg.location.stack().unwrap();
        let name = arg_name(arg);
        let ptr_name = format!("ptr_{}", name);
        stmts.push(cx.stmt_let(DUMMY_SP, false, cx.ident_of(&ptr_name),
            quote_expr!(cx, stack.offset(0 - $stack_size as isize - 1 + $pos as isize))));
    }
    for arg in func.args.iter().filter(|a| a.location.stack().is_some()) {
        let name = arg_name(arg);
        let ptr_name = format!("ptr_{}", name);
        let left = cx.expr_deref(DUMMY_SP, cx.expr_ident(DUMMY_SP, cx.ident_of(&ptr_name)));
        let right = expr_transmute_id(cx, sp, &arg_name(arg));
        stmts.push(cx.stmt_expr(P(ast::Expr {
            id: ast::DUMMY_NODE_ID,
            node: ExprKind::Assign(left, right),
            span: sp,
            attrs: None,
        })));
    }
}

fn returns_something(func: &nuottei::Function) -> bool {
    match func.ret_type {
        nuottei::Type::Default => false,
        nuottei::Type::Basic(s) => s != "void",
        _ => true,
    }
}

fn out_in_clobber(cx: &mut ExtCtxt, sp: Span, func: &nuottei::Function) -> (Vec<(InternedString, P<ast::Expr>)>, Vec<(InternedString, P<ast::Expr>)>, Vec<InternedString>) {
    let out = if returns_something(func) {
        vec![(InternedString::new("={eax}"), cx.expr_ident(sp, cx.ident_of("ret")))]
    } else {
        Vec::new()
    };
    let inputs: Vec<(InternedString, P<ast::Expr>)> = func.args.iter()
        .filter(|a| a.location.reg().is_some())
        .map(|a| (token::intern_and_get_ident(&format!("{{{}}}", a.location.reg().unwrap())),
                  cx.expr_ident(sp, cx.ident_of(&arg_name(a)))))
        .collect();
    let mut clobber = vec![InternedString::new("memory")];
    if out.len() == 0 && !inputs.iter().any(|tp| tp.0.find("eax").is_some()) {
        clobber.push(InternedString::new("eax"));
    }
    if !inputs.iter().any(|tp| tp.0.find("ecx").is_some()) {
        clobber.push(InternedString::new("ecx"));
    }
    if !inputs.iter().any(|tp| tp.0.find("edx").is_some()) {
        clobber.push(InternedString::new("edx"));
    }
    (out, inputs, clobber)
}

fn get_target_reg(func: &nuottei::Function) -> &'static str {
    let reg_arr = ["eax", "ecx", "edx", "ebx", "esi", "edi"];
    let canditates = if returns_something(func) {
        &reg_arr[1..]
    } else {
        &reg_arr[0..]
    };
    for cand in canditates {
        if !func.args.iter().any(|a| a.location.reg().and_then(|s| s.find(cand)).is_some()) {
            return cand;
        }
    }
    "whoops"
}

fn generate_asm_code(func: &nuottei::Function, target_reg: &str) -> InternedString {
    let mut result = String::new();
    let stack_arg_amt = func.args.iter().filter(|a| a.location.stack().is_some()).count();
    if stack_arg_amt != 0 {
        write!(result, "subl $${}, %esp\n", stack_arg_amt * 4).unwrap();
    }
    write!(result, "calll *%{}\n", target_reg).unwrap();
    if stack_arg_amt != 0 && func.attrs.iter().find(|&&s| s == "cdecl").is_some() {
        write!(result, "addl $${}, %esp\n", stack_arg_amt * 4).unwrap();
    }
    token::intern_and_get_ident(&result)
}

fn make_body(cx: &mut ExtCtxt, sp: Span, func: &nuottei::Function) -> P<ast::Block> {
    let mut statements = Vec::new();
    if returns_something(func) {
        statements.push(quote_stmt!(cx, let ret: usize;).unwrap());
    }
    add_stack_args(cx, sp, func, &mut statements);
    let (out, mut input, mut clob) = out_in_clobber(cx, sp, func);
    let target_reg = get_target_reg(func);
    let target_id = cx.ident_of("_target");
    let path = cx.path(DUMMY_SP, vec!(cx.ident_of("func_addr"), cx.ident_of(&func.name)));
    let addr = cx.expr_path(path);
    statements.push(cx.stmt_let_typed(sp, true, target_id, quote_ty!(cx, usize), addr).unwrap());
    input.push((token::intern_and_get_ident(&format!("{{{}}}", target_reg)), cx.expr_ident(sp, target_id)));
    if target_reg == "ecx" {
        clob.retain(|n| n.find("ecx").is_none());
    } else if target_reg == "edx" {
        clob.retain(|n| n.find("edx").is_none());
    }
    let asm_code = generate_asm_code(func, target_reg);
    let asm_expr = make_asm(cx, sp, asm_code, out, input, clob);
    statements.push(cx.stmt_expr(asm_expr));
    let ret_expr = match func.ret_type {
        nuottei::Type::Default => None,
        nuottei::Type::Basic(s) if s == "void" => None,
        nuottei::Type::Basic(s) if s == "bool" => Some(quote_expr!(cx, ret != 0)),
        _ => Some(expr_transmute_id(cx, sp, "ret"))
    };
    cx.block(sp, statements, ret_expr)
}

fn item_pub(sp: Span, name: ast::Ident, attrs: Vec<ast::Attribute>, node: ItemKind) -> P<ast::Item> {
    P(ast::Item {
        ident: name,
        attrs: attrs,
        id: ast::DUMMY_NODE_ID,
        node: node,
        vis: ast::Visibility::Public,
        span: sp
    })
}

fn item_pub_fn(cx: &ExtCtxt, sp: Span, name: ast::Ident, inputs: Vec<ast::Arg>, output: P<ast::Ty>, body: P<ast::Block>) -> P<ast::Item> {
    item_pub(sp, name, vec!(),
             ItemKind::Fn(cx.fn_decl(inputs, output),
                         ast::Unsafety::Unsafe,
                         ast::Constness::NotConst,
                         Abi::Rust,
                         Default::default(),
                         body))
}

fn ty_expr_from_var(cx: &ExtCtxt, sp: Span, var: &nuottei::Variable) -> Option<(P<ast::Ty>, P<ast::Expr>)> {
    to_rust_type(cx, sp, &var.tp, None).map(|t| {
        let path = cx.path_all(sp, true,
                                 vec!(
                                     cx.ident_of("whack"),
                                     cx.ident_of("Variable"),
                                 ),
                                 Vec::new(),
                                 vec!( t.clone() ),
                                 Vec::new());
        let expr = quote_expr!(cx, ::whack::Variable { address: !0, phantom: ::std::marker::PhantomData });
        (cx.ty_path(path), expr)
    })
}

fn static_method_sig(inputs: Vec<ast::Arg>, output: ast::FunctionRetTy) -> ast::MethodSig {
    ast::MethodSig {
        unsafety: ast::Unsafety::Normal,
        constness: ast::Constness::NotConst,
        abi: Abi::Rust,
        decl: P(ast::FnDecl {
            inputs: inputs,
            output: output,
            variadic: false,
        }),
        generics: Default::default(),
        explicit_self: Spanned {
            node: ast::SelfKind::Static,
            span: DUMMY_SP,
        },
    }
}

fn hook_impl(cx: &mut ExtCtxt, sp: Span, func: &nuottei::Function) -> Vec<ast::ImplItem> {
    let mut asm_code = "int3\n".to_string();
    let mut stack_pos = 0usize;
    for arg in func.args.iter().rev() {
        match arg.location {
            Stack(pos) => {
                let arg_pos = (stack_pos + pos as usize) * mem::size_of::<usize>();
                write!(asm_code, "push 0x{:x}(%esp)\n", arg_pos).unwrap();
            }
            Register(ref reg) => write!(asm_code, "push %{}\n", reg).unwrap(),
        }
        stack_pos += 1;
    }
    let stack_size = match func.attrs.iter().find(|&&x| x == "cdecl").is_some() {
        true => 0,
        false => func.args.iter().filter(|a| a.location.stack().is_some()).count(),
    };
    let arg_count = func.args.len();
    write!(asm_code, "mov $$0xcccccccc, %eax\n calll *%eax\n").unwrap();
    write!(asm_code, "addl $${}, %esp\n", arg_count * mem::size_of::<usize>()).unwrap();
    write!(asm_code, "retl $${}", stack_size * mem::size_of::<usize>()).unwrap();
    let asm_expr = make_asm(cx, sp, token::intern_and_get_ident(&asm_code), vec!(), vec!(), vec!());
    let sig = static_method_sig(vec!(), ast::FunctionRetTy::Default(sp));
    let block = cx.block(sp, vec!(),
        Some(cx.expr_block(unsafe_block(sp, vec!(cx.stmt_expr(asm_expr)), None))));
    let asm_code_fn = ast::ImplItem {
        id: ast::DUMMY_NODE_ID,
        ident: cx.ident_of("__asm_code"),
        vis: ast::Visibility::Inherited,
        attrs: vec!(),
        node: ast::ImplItemKind::Method(sig, block),
        span: sp,
    };
    vec!(asm_code_fn)
}

fn hook_get_wrapper(cx: &mut ExtCtxt, sp: Span, func: &nuottei::Function, expected_base: usize) -> Vec<ast::ImplItem> {
    let output = ast::FunctionRetTy::Ty(quote_ty!(cx, *const u8));
    let sig = ast::MethodSig {
        unsafety: ast::Unsafety::Unsafe,
        constness: ast::Constness::NotConst,
        abi: Abi::Rust,
        decl: P(ast::FnDecl {
            inputs: vec!(),
            output: output,
            variadic: false,
        }),
        generics: Default::default(),
        explicit_self: Spanned {
            node: ast::SelfKind::Static,
            span: sp,
        },
    };
    let addr_sig = static_method_sig(vec!(), ast::FunctionRetTy::Ty(quote_ty!(cx, usize)));
    let expected_base_sig = static_method_sig(vec!(), ast::FunctionRetTy::Ty(quote_ty!(cx, usize)));
    let asm_code_stmt = quote_stmt!(cx, let addr: *const *const u8 = ::std::mem::transmute(&Self::__asm_code)).unwrap();
    let asm_expr = quote_expr!(cx, *addr);

    let block = cx.block(sp, vec!(asm_code_stmt), Some(asm_expr));
    let addr = func.address as usize;
    let addr_block = cx.block(sp, vec!(), Some(quote_expr!(cx, $addr)));
    let expected_base_block = cx.block(sp, vec!(), Some(quote_expr!(cx, $expected_base)));
    let impl_item = |name, node| ast::ImplItem {
        id: ast::DUMMY_NODE_ID,
        ident: cx.ident_of(name),
        vis: ast::Visibility::Inherited,
        attrs: vec!(),
        node: node,
        span: sp,
    };
    let get_wrapper = impl_item("get_hook_wrapper", ast::ImplItemKind::Method(sig, block));
    let address = impl_item("address", ast::ImplItemKind::Method(addr_sig, addr_block));
    let expected_base = impl_item("expected_base",
                                  ast::ImplItemKind::Method(expected_base_sig, expected_base_block));
        unsafety: ast::Unsafety::Unsafe,
        abi: Abi::C,
        lifetimes: vec!(),
        decl: P(ast::FnDecl {
            inputs: make_inputs(cx, sp, func),
            output: ast::FunctionRetTy::Ty(to_rust_type(cx, sp, &func.ret_type, Some(unit_ty(cx, sp))).unwrap()),
            variadic: false,
        }),
    })));
    vec!(get_wrapper, address, expected_base, target_type_impl)
}

fn item_impl(cx: &mut ExtCtxt, trait_path: Option<ast::Path>, struct_ty: P<ast::Ty>, items: Vec<ast::ImplItem>) -> P<ast::Item> {
    cx.item(DUMMY_SP, cx.ident_of(""), vec!(), ItemKind::Impl(
        ast::Unsafety::Normal,
        ast::ImplPolarity::Positive,
        Default::default(),
        trait_path.map(|x| ast::TraitRef { path: x, ref_id: ast::DUMMY_NODE_ID }),
        struct_ty,
        items
    ))
}

/// Common iterate lines/sections with spans -loop for all macros
/// The callbacks are becoming unnecessarily complicated <.<
fn parse_file<Func, Var, Section>(cx: &mut ExtCtxt, sp: Span, args: &[TokenTree],
                                  mut handle_func: Func, mut handle_var: Var, mut section_end: Section
                                 ) -> Box<MacResult + 'static>
where Func: FnMut(nuottei::Function, &mut ExtCtxt, Span, &mut Vec<P<ast::Item>>, u64),
      Var: FnMut(nuottei::Variable, &mut ExtCtxt, Span, &mut Vec<P<ast::Item>>),
      Section: FnMut(u64, &mut ExtCtxt, Span, &mut Vec<P<ast::Item>>, &Vec<(&str, usize)>, &Vec<(&str, usize)>) {
    let filename = match parse(cx, args) {
        Some(f) => f,
        None => return DummyResult::any(sp),
    };
    let mut full_filename = PathBuf::from(cx.codemap().span_to_filename(cx.expansion_cause()));
    full_filename.pop();
    full_filename.push(&filename);

    let text_contents = match fs::File::open(&full_filename) {
        Ok(mut f) => {
            let mut text = String::new();
            if let Err(e) = f.read_to_string(&mut text) {
                cx.span_err(sp, &format!("Error when reading file {}: {}", &filename, e));
                return DummyResult::any(sp);
            }
            text
        }
        Err(e) => {
            cx.span_err(sp, &format!("Error when reading file {}: {}", &filename, e));
            return DummyResult::any(sp);
        }
    };

    let full_filename = match full_filename.into_os_string().into_string() {
        Ok(o) => o,
        Err(_) => {
            cx.span_err(sp, "Strange characters in path");
            return DummyResult::any(sp);
        }
    };
    let filemap = cx.codemap().new_filemap(full_filename, text_contents.clone());
    filemap.next_line(filemap.start_pos);

    let mut filemap_pos = filemap.start_pos;
    let mut items = Vec::new();
    let mut current_section = "";
    let mut current_base = 0;
    let mut current_section_span = DUMMY_SP;
    let mut sections = Vec::new();
    // For generating base addr init funs
    let mut funcs = Vec::new();
    let mut vars = Vec::new();

    let super_path = cx.path(DUMMY_SP, vec!(cx.ident_of("super")));
    items.push(cx.item_use(DUMMY_SP, ast::Visibility::Inherited, P(ast::ViewPath {
        node: ast::ViewPathGlob(super_path.clone()),
        span: DUMMY_SP,
    })));
    for line in text_contents.lines() {
        let span = Span {
            lo: filemap_pos,
            hi: filemap_pos + Pos::from_usize(line.len()),
            expn_id: cx.backtrace
        };
        match nuottei::parse_line(line, &nuottei::ParseSettings::loose()) {
            Ok(Declaration::Function(func)) => {
                funcs.push((func.name.clone(), func.address as usize));
                handle_func(func, cx, span, &mut items, current_base);
            }
            Ok(Declaration::Variable(var)) => {
                vars.push((var.name.clone(), var.address as usize));
                handle_var(var, cx, span, &mut items);
            }
            Ok(Declaration::Comment(_)) => (),
            Ok(Declaration::Section(sect)) => {
                // FIXME? Could just have items be in root namespace
                if current_section == "" {
                    if items.len() > 1 {
                        cx.span_err(span, "No section before first entry");
                    }
                } else {
                    section_end(current_base, cx, current_section_span, &mut items, &vars, &funcs);
                    sections.push(item_pub(current_section_span, cx.ident_of(current_section),
                                           vec!(quote_attr!(cx, #[allow(non_snake_case)])),
                                           ItemKind::Mod(ast::Mod {
                                               inner: current_section_span,
                                               items: items,
                                           })));
                }
                items = Vec::new();
                items.push(cx.item_use(DUMMY_SP, ast::Visibility::Inherited, P(ast::ViewPath {
                    node: ast::ViewPathGlob(super_path.clone()),
                    span: DUMMY_SP,
                })));
                current_section = sect.name;
                current_base = sect.base.unwrap_or(current_base);
                current_section_span = span;
                funcs.clear();
                vars.clear();
            }
            Err((err, _)) => cx.span_err(span, &err.description),
        }
        filemap_pos = filemap_pos + Pos::from_usize(line.len() + 1);
        filemap.next_line(filemap_pos);
    }
    if current_section == "" {
        if items.len() > 1 {
            cx.span_err(DUMMY_SP, "No section before first entry");
        }
    } else {
        // FIXME: Incorrect span
        section_end(current_base, cx, DUMMY_SP, &mut items, &vars, &funcs);
        sections.push(item_pub(DUMMY_SP, cx.ident_of(current_section),
                               vec!(quote_attr!(cx, #[allow(non_snake_case)])),
                               ItemKind::Mod(ast::Mod {
                                   inner: DUMMY_SP,
                                   items: items,
                               })));
    }
    MacEager::items(SmallVector::many(sections))
}

/// Generates code for `init_module_vars()`, setting addresses of variables and
/// functions to correct values
fn init_module_body<'a, I, J>(cx: &mut ExtCtxt, vars: I, funcs: J, base: usize) -> P<ast::Block>
where I: Iterator<Item=&'a (&'a str, usize)>,
      J: Iterator<Item=&'a (&'a str, usize)>, {
    let mut statements = Vec::new();
    statements.push(quote_stmt!(cx, let base: usize = ::std::mem::transmute(ptr);).unwrap());
    for var in vars {
        let offset = var.1 - base;
        let field_expr = cx.expr(DUMMY_SP, ExprKind::Field(cx.expr_ident(DUMMY_SP, cx.ident_of(&var.0)), Spanned {
            node: cx.ident_of("address"),
            span: DUMMY_SP,
        }));
        let expr = ExprKind::Assign(field_expr,
                                   quote_expr!(cx, base + $offset));
        statements.push(cx.stmt_expr(cx.expr(DUMMY_SP, expr)));
    }
    for func in funcs {
        let offset = func.1 - base;
        let path = cx.path(DUMMY_SP, vec!(cx.ident_of("func_addr"), cx.ident_of(&func.0)));
        let expr = ExprKind::Assign(cx.expr_path(path), quote_expr!(cx, base + $offset));
        statements.push(cx.stmt_expr(cx.expr(DUMMY_SP, expr)));
    }
    cx.block(DUMMY_SP, statements, None)
}

/// Generates static variables containing function addresses
fn make_func_addrs<'a, I>(cx: &mut ExtCtxt, funcs: I) -> Vec<P<ast::Item>>
where I: Iterator<Item=&'a (&'a str, usize)> {
    funcs.map(|&(ref name, _)| {
        let node = ItemKind::Static(quote_ty!(cx, usize), ast::Mutability::Mutable, quote_expr!(cx, !0));
        item_pub(DUMMY_SP, cx.ident_of(&name), vec!(), node)
    }).collect()
}

fn generate_from_txt(cx: &mut ExtCtxt, sp: Span, args: &[TokenTree]) -> Box<MacResult + 'static> {
    parse_file(cx, sp, args, |func, cx, span, items, _base| {
        let inputs = make_inputs(cx, span, &func);
        let output = to_rust_type(cx, span, &func.ret_type, Some(unit_ty(cx, sp))).unwrap();
        let body = make_body(cx, span, &func);
        items.push(item_pub_fn(cx, span, cx.ident_of(&func.name), inputs, output, body));
    }, |var, cx, span, items| {
        match ty_expr_from_var(cx, span, &var) {
            Some((ty, expr)) => {
                let node = ItemKind::Static(ty, ast::Mutability::Mutable, expr);
                items.push(item_pub(span, cx.ident_of(&var.name), vec!(), node));
            }
            None => {
                cx.span_err(span, &format!("Variable {} does not have a type", var.name));
            }
        };
    }, |base, cx, span, items, vars, funcs| {
        let input = cx.arg(span, cx.ident_of("ptr"), quote_ty!(cx, *const ::std::os::raw::c_void));
        let body = init_module_body(cx, vars.iter(), funcs.iter(), base as usize);
        let func_addrs = make_func_addrs(cx, funcs.iter());
        items.push(item_pub_fn(cx, span, cx.ident_of("init_module_vars"), vec!(input), unit_ty(cx, span), body));
        items.push(cx.item(DUMMY_SP, cx.ident_of("func_addr"), vec!(),
                               ItemKind::Mod(ast::Mod {
                                   inner: DUMMY_SP,
                                   items: func_addrs,
                               })));
    })
}

fn generate_hooks(cx: &mut ExtCtxt, sp: Span, args: &[TokenTree]) -> Box<MacResult + 'static> {
    let hook_path = cx.path_global(DUMMY_SP, vec!(cx.ident_of("whack"), cx.ident_of("HookableAsmWrap")));
    parse_file(cx, sp, args, |func, cx, span, items, base| {
        let struct_ty = cx.ty_ident(span, cx.ident_of(&func.name));
        let hook_impl = hook_impl(cx, span, &func);
        let get_wrapper = hook_get_wrapper(cx, span, &func, base as usize);
        items.push(item_pub(span, cx.ident_of(&func.name), vec!(),
                            ItemKind::Struct(
                                ast::VariantData::Unit(ast::DUMMY_NODE_ID),
                                Default::default())));

        items.push(item_impl(cx, None, struct_ty.clone(), hook_impl));
        items.push(item_impl(cx, Some(hook_path.clone()), struct_ty, get_wrapper));
    }, |_var, cx, span, _items| {
        cx.span_err(span, "Unexpected variable in hooks file");
    }, |_base, _cx, _span, _items, _vars, _funcs| {
        // Do nothing
    })
}

// Taken from regex_macros package, all credit to them
fn parse(cx: &mut ExtCtxt, tts: &[TokenTree]) -> Option<String> {
    let mut parser = cx.new_parser_from_tts(tts);
    let entry = {
        let expr = match parser.parse_expr() {
            Ok(e) => e,
            Err(mut diag) => {
                diag.emit();
                return None;
            }
        };
        cx.expander().fold_expr(expr)
    };
    let filename = match entry.node {
        ExprKind::Lit(ref lit) => {
            match lit.node {
                ast::LitKind::Str(ref s, _) => s.to_string(),
                _ => {
                    cx.span_err(entry.span, &format!(
                        "expected string literal but got `{}`",
                        pprust::lit_to_string(&**lit)));
                    return None
                }
            }
        }
        _ => {
            cx.span_err(entry.span, &format!(
                "expected string literal but got `{}`",
                pprust::expr_to_string(&*entry)));
            return None
        }
    };
    if !parser.eat(&token::Eof) {
        cx.span_err(parser.span, "only one string literal allowed");
        return None;
    }
    Some(filename)
}
