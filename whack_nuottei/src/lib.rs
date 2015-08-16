#![crate_type="dylib"]
#![feature(quote, plugin_registrar, slice_patterns, rustc_private, convert)]

extern crate nuottei;
extern crate rustc;
extern crate syntax;

use syntax::codemap::{DUMMY_SP, Span, Spanned, Pos};
use syntax::ast::{self, TokenTree};
use syntax::ext::build::AstBuilder;
use syntax::ext::base::{ExtCtxt, MacResult, DummyResult, MacEager};
use syntax::parse::token::{self, InternedString};
use syntax::print::pprust;
use syntax::util::small_vector::SmallVector;
use syntax::fold::Folder;
use syntax::ptr::P;
use syntax::{ast_util, abi};
use rustc::plugin::Registry;
use std::path::PathBuf;
use std::mem;
use std::fmt::Write;
use std::fs;
use std::io::Read;

use nuottei::{ParseResult, Stack, Register};

#[plugin_registrar]
pub fn plugin_registrar(reg: &mut Registry) {
    reg.register_macro("import_nuottei", generate_from_txt);
    reg.register_macro("import_hooks", generate_hooks);
}

fn unit_ty(cx: &ExtCtxt, sp: Span) -> P<ast::Ty> {
    cx.ty(sp, ast::TyTup(Vec::new()))
}

fn to_rust_type(cx: &ExtCtxt, sp: Span, input: &nuottei::Type, default_ty: Option<P<ast::Ty>>) -> Option<P<ast::Ty>> {
    match *input {
        nuottei::Type::Basic(ref name) => {
            Some(match name.as_str() {
                "dword" => quote_ty!(cx, u32),
                "int" => quote_ty!(cx, i32),
                "word" => quote_ty!(cx, u16),
                "byte" => quote_ty!(cx, u8),
                "char" => quote_ty!(cx, ::std::os::raw::c_char),
                "void" => quote_ty!(cx, ::std::os::raw::c_void),
                n => cx.ty_ident(sp, cx.ident_of(n)),
            })
        }
        nuottei::Type::Pointer(mutable, ref inner) => to_rust_type(cx, sp, inner, default_ty)
            .map(|t| cx.ty_ptr(sp, t, if mutable { ast::MutMutable } else { ast::MutImmutable })),
        nuottei::Type::Array(size, ref inner) => to_rust_type(cx, sp, inner, default_ty)
            .map(|t| cx.ty(sp, ast::TyFixedLengthVec(t, cx.expr_usize(sp, size as usize)))),
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

fn unsafe_block(sp: Span, stmts: Vec<P<ast::Stmt>>, expr: Option<P<ast::Expr>>) -> P<ast::Block> {
    P(ast::Block {
        stmts: stmts,
        expr: expr,
        id: ast::DUMMY_NODE_ID,
        rules: ast::UnsafeBlock(ast::CompilerGenerated), // Not sure about CompilerGenerated
        span: sp,
    })
}

fn make_asm(cx: &ExtCtxt, sp: Span, asm: InternedString, outputs: Vec<(InternedString, P<ast::Expr>)>,
    inputs: Vec<(InternedString, P<ast::Expr>)>, clobbers: Vec<InternedString>) -> P<ast::Expr> {
    cx.expr(sp, ast::ExprInlineAsm(ast::InlineAsm {
        asm: asm,
        asm_str_style: ast::StrStyle::CookedStr,
        outputs: outputs.into_iter().map(|tp| (tp.0, tp.1, false)).collect(),
        inputs: inputs,
        clobbers: clobbers,
        volatile: true,
        alignstack: false,
        dialect: ast::AsmDialect::AsmAtt,
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

fn add_stack_args(cx: &ExtCtxt, sp: Span, func: &nuottei::Function, stmts: &mut Vec<P<ast::Stmt>>) {
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
            node: ast::ExprAssign(left, right),
            span: sp
        })));
    }
}

fn returns_something(func: &nuottei::Function) -> bool {
    match func.ret_type {
        nuottei::Type::Default => false,
        nuottei::Type::Basic(ref s) => s != "void",
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
        .map(|a| (token::intern_and_get_ident(&format!("{{{}}}", a.location.reg().unwrap())), cx.expr_ident(sp, cx.ident_of(&arg_name(a)))))
        .collect();
    let mut clobber = vec![InternedString::new("memory")];
    if out.len() == 0 && !inputs.iter().any(|tp| tp.0.find("eax").is_some()) {
        clobber.push(InternedString::new("{eax}"));
    }
    if !inputs.iter().any(|tp| tp.0.find("ecx").is_some()) {
        clobber.push(InternedString::new("{ecx}"));
    }
    if !inputs.iter().any(|tp| tp.0.find("edx").is_some()) {
        clobber.push(InternedString::new("{edx}"));
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
    let stack_arg_amt = func.args.iter().filter(|a| a.location.stack().is_some()).count();
    let stack_ins = if stack_arg_amt != 0 {
        format!("subl $${}, %esp\n\t", stack_arg_amt * 4)
    } else {
        "".to_string()
    };
    token::intern_and_get_ident(&format!("{}calll *%{}", stack_ins, target_reg))
}

fn make_body(cx: &mut ExtCtxt, sp: Span, func: &nuottei::Function) -> P<ast::Block> {
    let mut statements = Vec::new();
    if returns_something(func) {
        statements.push(quote_stmt!(cx, let ret: usize;).unwrap());
    }
    add_stack_args(cx, sp, func, &mut statements);
    let (out, mut input, clob) = out_in_clobber(cx, sp, func);
    let target_reg = get_target_reg(func);
    let target_id = cx.ident_of("_target");
    statements.push(cx.stmt_let_typed(sp, true, target_id, cx.ty_ident(sp, cx.ident_of("usize")), cx.expr_usize(sp, func.address as usize)));
    input.push((token::intern_and_get_ident(&format!("{{{}}}", target_reg)), cx.expr_ident(sp, target_id)));
    let asm_code = generate_asm_code(func, target_reg);
    let asm_expr = make_asm(cx, sp, asm_code, out, input, clob);
    statements.push(cx.stmt_expr(asm_expr));
    let ret_expr = match func.ret_type {
        nuottei::Type::Default => None,
        nuottei::Type::Basic(ref s) if s == "void" => None,
        nuottei::Type::Basic(ref s) if s == "bool" => Some(quote_expr!(cx, ret != 0)),
        _ => Some(expr_transmute_id(cx, sp, "ret"))
    };
    cx.block(sp, statements, ret_expr)
}

fn item_pub(sp: Span, name: ast::Ident, node: ast::Item_) -> P<ast::Item> {
    P(ast::Item {
        ident: name,
        attrs: Vec::new(),
        id: ast::DUMMY_NODE_ID,
        node: node,
        vis: ast::Public,
        span: sp
    })
}

fn item_pub_fn(cx: &ExtCtxt, sp: Span, name: ast::Ident, inputs: Vec<ast::Arg>, output: P<ast::Ty>, body: P<ast::Block>) -> P<ast::Item> {
    item_pub(sp, name,
             ast::ItemFn(cx.fn_decl(inputs, output),
                         ast::Unsafety::Unsafe,
                         ast::Constness::NotConst,
                         abi::Rust,
                         ast_util::empty_generics(),
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
        let addr = var.address as usize;
        let expr = quote_expr!(cx, ::whack::Variable { address: $addr, phantom: ::std::marker::PhantomData });
        (cx.ty_path(path), expr)
    })
}

fn static_method_sig(inputs: Vec<ast::Arg>, output: ast::FunctionRetTy) -> ast::MethodSig {
    ast::MethodSig {
        unsafety: ast::Unsafety::Normal,
        constness: ast::Constness::NotConst,
        abi: ::syntax::abi::Abi::Rust,
        decl: P(ast::FnDecl {
            inputs: inputs,
            output: output,
            variadic: false,
        }),
        generics: ast_util::empty_generics(),
        explicit_self: Spanned {
            node: ast::SelfStatic,
            span: DUMMY_SP,
        },
    }
}

fn hook_impl(cx: &mut ExtCtxt, sp: Span, func: &nuottei::Function) -> Vec<P<ast::ImplItem>> {
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
    let stack_size = func.args.iter().filter(|a| a.location.stack().is_some()).count();
    let arg_count = func.args.len();
    write!(asm_code, "mov $$0xcccccccc, %eax\n calll *%eax\n addl $${}, %esp\n retl $${}",
           arg_count * mem::size_of::<usize>(), stack_size * mem::size_of::<usize>()).unwrap();
    let asm_expr = make_asm(cx, sp, token::intern_and_get_ident(&asm_code), vec!(), vec!(), vec!());
    let sig = static_method_sig(vec!(), ast::DefaultReturn(sp));
    let block = cx.block(sp, vec!(),
        Some(cx.expr_block(unsafe_block(sp, vec!(cx.stmt_expr(asm_expr)), None))));
    let asm_code_fn = P(ast::ImplItem {
        id: ast::DUMMY_NODE_ID,
        ident: cx.ident_of("__asm_code"),
        vis: ast::Inherited,
        attrs: vec!(),
        node: ast::MethodImplItem(sig, block),
        span: sp,
    });
    vec!(asm_code_fn)
}

fn hook_get_wrapper(cx: &mut ExtCtxt, sp: Span, func: &nuottei::Function, expected_base: usize) -> Vec<P<ast::ImplItem>> {
    let output = ast::Return(quote_ty!(cx, *const u8));
    let sig = ast::MethodSig {
        unsafety: ast::Unsafety::Unsafe,
        constness: ast::Constness::NotConst,
        abi: ::syntax::abi::Abi::Rust,
        decl: P(ast::FnDecl {
            inputs: vec!(),
            output: output,
            variadic: false,
        }),
        generics: ast_util::empty_generics(),
        explicit_self: Spanned {
            node: ast::SelfStatic,
            span: sp,
        },
    };
    let addr_sig = static_method_sig(vec!(), ast::Return(quote_ty!(cx, usize)));
    let expected_base_sig = static_method_sig(vec!(), ast::Return(quote_ty!(cx, usize)));
    let asm_code_stmt = quote_stmt!(cx, let addr: *const *const u8 = ::std::mem::transmute(&Self::__asm_code)).unwrap();
    let asm_expr = quote_expr!(cx, *addr);

    let block = cx.block(sp, vec!(asm_code_stmt), Some(asm_expr));
    let addr = func.address as usize;
    let addr_block = cx.block(sp, vec!(), Some(quote_expr!(cx, $addr)));
    let expected_base_block = cx.block(sp, vec!(), Some(quote_expr!(cx, $expected_base)));
    let get_wrapper = P(ast::ImplItem {
        id: ast::DUMMY_NODE_ID,
        ident: cx.ident_of("get_hook_wrapper"),
        vis: ast::Inherited,
        attrs: vec!(),
        node: ast::MethodImplItem(sig, block),
        span: sp,
    });
    let address = P(ast::ImplItem {
        id: ast::DUMMY_NODE_ID,
        ident: cx.ident_of("address"),
        vis: ast::Inherited,
        attrs: vec!(),
        node: ast::MethodImplItem(addr_sig, addr_block),
        span: sp,
    });
    let expected_base = P(ast::ImplItem {
        id: ast::DUMMY_NODE_ID,
        ident: cx.ident_of("expected_base"),
        vis: ast::Inherited,
        attrs: vec!(),
        node: ast::MethodImplItem(expected_base_sig, expected_base_block),
        span: sp,
    });
    let target_type = cx.ty(sp, ast::TyBareFn(P(ast::BareFnTy {
        unsafety: ast::Unsafety::Unsafe,
        abi: abi::Abi::C,
        lifetimes: vec!(),
        decl: P(ast::FnDecl {
            inputs: make_inputs(cx, sp, func),
            output: ast::Return(to_rust_type(cx, sp, &func.ret_type, Some(unit_ty(cx, sp))).unwrap()),
            variadic: false,
        }),
    })));
    let target_type_impl = P(ast::ImplItem {
        id: ast::DUMMY_NODE_ID,
        ident: cx.ident_of("Target"),
        vis: ast::Inherited,
        attrs: vec!(),
        node: ast::TypeImplItem(target_type),
        span: sp,
    });
    vec!(get_wrapper, address, expected_base, target_type_impl)
}

fn item_impl(cx: &mut ExtCtxt, trait_path: Option<ast::Path>, struct_ty: P<ast::Ty>, items: Vec<P<ast::ImplItem>>) -> P<ast::Item> {
    cx.item(DUMMY_SP, cx.ident_of(""), vec!(), ast::ItemImpl(
        ast::Unsafety::Normal,
        ast::ImplPolarity::Positive,
        ast_util::empty_generics(),
        trait_path.map(|x| ast::TraitRef { path: x, ref_id: ast::DUMMY_NODE_ID }),
        struct_ty,
        items
    ))
}

/// Common iterate lines/sections with spans -loop for all macros
fn parse_file<Func, Var>(cx: &mut ExtCtxt, sp: Span, args: &[TokenTree],
                         mut handle_func: Func, mut handle_var: Var) -> Box<MacResult + 'static>
where Func: FnMut(nuottei::Function, &mut ExtCtxt, Span, &mut Vec<P<ast::Item>>, u64),
      Var: FnMut(nuottei::Variable, &mut ExtCtxt, Span, &mut Vec<P<ast::Item>>) {
    let filename = match parse(cx, args) {
        Some(f) => f,
        None => return DummyResult::any(sp),
    };
    let mut full_filename = PathBuf::from(cx.codemap().span_to_filename(cx.expansion_cause()));
    full_filename.pop();
    full_filename.push(filename.clone());

    let text_contents = match fs::File::open(full_filename) {
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

    let filemap = cx.codemap().new_filemap(filename, text_contents.clone());
    filemap.next_line(filemap.start_pos);

    let mut filemap_pos = filemap.start_pos;
    let mut items = Vec::new();
    let mut current_section = String::new();
    let mut current_base = 0;
    let mut sections = Vec::new();
    let super_path = cx.path(DUMMY_SP, vec!(cx.ident_of("super")));
    items.push(cx.item_use(DUMMY_SP, ast::Inherited, P(ast::ViewPath {
        node: ast::ViewPathGlob(super_path.clone()),
        span: DUMMY_SP,
    })));
    for line in text_contents.lines() {
        let span = Span {
            lo: filemap_pos,
            hi: filemap_pos + Pos::from_usize(line.len()),
            expn_id: cx.backtrace
        };
        match nuottei::parse_line(line, nuottei::DefaultMutability::None) {
            Ok(ParseResult::Function(func)) => handle_func(func, cx, span, &mut items, current_base),
            Ok(ParseResult::Variable(var)) => handle_var(var, cx, span, &mut items),
            Ok(ParseResult::Nothing) => (),
            Ok(ParseResult::Section(name, base)) => {
                // FIXME? Could just have items be in root namespace
                if current_section == "" {
                    if items.len() > 1 {
                        cx.span_err(span, "No section before first entry");
                    }
                } else {
                    // FIXME: Incorrect span
                    sections.push(item_pub(span, cx.ident_of(&current_section),
                                           ast::ItemMod(ast::Mod {
                                               inner: span,
                                               items: items,
                                           })));
                }
                items = Vec::new();
                items.push(cx.item_use(DUMMY_SP, ast::Inherited, P(ast::ViewPath {
                    node: ast::ViewPathGlob(super_path.clone()),
                    span: DUMMY_SP,
                })));
                current_section = name;
                current_base = base.unwrap_or(current_base);
            }
            Err(desc) => cx.span_err(span, &desc),
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
        sections.push(item_pub(DUMMY_SP, cx.ident_of(&current_section),
                               ast::ItemMod(ast::Mod {
                                   inner: DUMMY_SP,
                                   items: items,
                               })));
    }
    MacEager::items(SmallVector::many(sections))
}

fn generate_from_txt(cx: &mut ExtCtxt, sp: Span, args: &[TokenTree]) -> Box<MacResult + 'static> {
    // FIXME: _base
    parse_file(cx, sp, args, |func, cx, span, items, _base| {
        let inputs = make_inputs(cx, span, &func);
        let output = to_rust_type(cx, span, &func.ret_type, Some(unit_ty(cx, sp))).unwrap();
        let body = make_body(cx, span, &func);
        items.push(item_pub_fn(cx, span, cx.ident_of(&func.name), inputs, output, body));
    }, |var, cx, span, items| {
        match ty_expr_from_var(cx, span, &var) {
            Some((ty, expr)) => {
                items.push(item_pub(span, cx.ident_of(&var.name), ast::ItemStatic(ty, ast::MutMutable, expr)));
            }
            None => {
                cx.span_err(span, &format!("Variable {} does not have a type", var.name));
            }
        };
    })
}

fn generate_hooks(cx: &mut ExtCtxt, sp: Span, args: &[TokenTree]) -> Box<MacResult + 'static> {
    let hook_path = cx.path_global(DUMMY_SP, vec!(cx.ident_of("whack"), cx.ident_of("HookableAsmWrap")));
    parse_file(cx, sp, args, |func, cx, span, items, base| {
        let struct_ty = cx.ty_ident(span, cx.ident_of(&func.name));
        let hook_impl = hook_impl(cx, span, &func);
        let get_wrapper = hook_get_wrapper(cx, span, &func, base as usize);
        items.push(item_pub(span, cx.ident_of(&func.name),
                            ast::ItemStruct(
                                P(ast::StructDef {
                                    fields: vec!(),
                                    ctor_id: Some(ast::DUMMY_NODE_ID),
                                }),
                                ast_util::empty_generics())));

        items.push(item_impl(cx, None, struct_ty.clone(), hook_impl));
        items.push(item_impl(cx, Some(hook_path.clone()), struct_ty, get_wrapper));
    }, |_var, cx, span, _items| {
        cx.span_err(span, "Unexpected variable in hooks file");
    })
}

// Taken from regex_macros package, all credit to them
fn parse(cx: &mut ExtCtxt, tts: &[TokenTree]) -> Option<String> {
    let mut parser = cx.new_parser_from_tts(tts);
    let entry = cx.expander().fold_expr(parser.parse_expr());
    let filename = match entry.node {
        ast::ExprLit(ref lit) => {
            match lit.node {
                ast::LitStr(ref s, _) => s.to_string(),
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
    if !parser.eat(&token::Eof).ok().unwrap() {
        cx.span_err(parser.span, "only one string literal allowed");
        return None;
    }
    Some(filename)
}
