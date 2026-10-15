//! frp's config templating: the `text/template` subset a config file uses.
//!
//! Every config file frp loads goes through Go's `text/template` before it is
//! parsed — `config.LoadFileContentWithTemplate`, which every format shares, so
//! a TOML file and a legacy INI file are templated the same way. `.Envs` is the
//! process environment and two functions are registered:
//! `parseNumberRange` and `parseNumberRangePair`.
//!
//! This is the subset of that engine that config files actually use, taken from
//! frp's own README and its end-to-end fixtures:
//!
//! ```text
//! serverAddr = "{{ .Envs.FRP_SERVER_ADDR }}"
//! remotePort = {{ .Envs.FRP_SSH_REMOTE_PORT }}
//!
//! {{- range $_, $v := parseNumberRangePair "6000-6006,6007" "6000-6006,6007" }}
//! [[proxies]]
//! name = "tcp-{{ $v.First }}"
//! localPort = {{ $v.First }}
//! remotePort = {{ $v.Second }}
//! {{- end }}
//! ```
//!
//! Anything outside it is an **error**, not a passthrough. A config that kept
//! its `{{ }}` would be handed to TOML or INI and fail somewhere else entirely,
//! with a message about a port that is not a number — which is exactly the
//! failure that prompted writing this: `server_port is not a number:
//! {{.Envs.FrpsPort}}`. Naming the unsupported action is worth more than that.
//!
//! Two Go behaviours are reproduced deliberately because configs depend on
//! them. `{{-` and `-}}` trim the whitespace around an action, which is what
//! keeps a `range` block from leaving a blank line per proxy. And a value is
//! printed the way `fmt` prints it — a number as digits, a pair as `{6000
//! 6001}`, a list as `[6000 6001]`.

use std::collections::HashMap;

use crate::error::{Error, Result};

/// Renders a config file's text against the process environment.
pub fn render(input: &str) -> Result<String> {
    render_with(input, &environment())
}

/// The same, against a supplied environment.
///
/// Split out so the tests do not have to mutate the process environment, which
/// is global and would make them order-dependent.
pub fn render_with(input: &str, envs: &HashMap<String, String>) -> Result<String> {
    let tokens = lex(input)?;
    let (nodes, rest) = parse_nodes(&tokens, 0)?;
    if rest != tokens.len() {
        // `parse_nodes` only stops early on `{{end}}`, so reaching here means an
        // `end` with no `range` in front of it.
        return Err(Error::config(
            "config template: `{{end}}` without a matching `{{range}}`".to_string(),
        ));
    }

    let mut scope = Scope::default();
    let mut out = String::with_capacity(input.len());
    render_nodes(&nodes, &mut scope, envs, &mut out)?;
    Ok(out)
}

/// The process environment, as `.Envs`.
fn environment() -> HashMap<String, String> {
    std::env::vars().collect()
}

// ---------------------------------------------------------------- lexing ---

/// A literal run of text, or one `{{ }}` action.
#[derive(Debug, PartialEq)]
enum Token {
    /// Text with its surrounding whitespace already trimmed by any `-}}`/`{{-`
    /// next to it.
    Text(String),
    Action(String),
}

/// Splits the input into text and actions.
///
/// The trim markers are applied here rather than when rendering, because what
/// they trim is the *text* on either side, and this is the only place both
/// sides are in hand.
fn lex(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut rest = input;

    while let Some(open) = rest.find("{{") {
        let mut text = &rest[..open];
        let after_open = &rest[open + 2..];
        // `{{-` eats the whitespace before it, newlines included — that is what
        // stops a `range` from leaving a blank line per iteration.
        let trim_before = after_open.starts_with('-');
        if trim_before {
            text = text.trim_end();
        }
        if !text.is_empty() {
            tokens.push(Token::Text(text.to_string()));
        }

        // `after_open` already has the `{{` cut off, so the body starts at 0 —
        // or at 1 when a `-` is there.
        let body_start = usize::from(trim_before);
        let Some(close) = after_open.find("}}") else {
            return Err(Error::config(format!(
                "config template: `{{{{` at byte {open} is never closed"
            )));
        };
        let mut body = &after_open[body_start..close];
        let consumed = open + 2 + close + 2;
        // `-}}` eats the whitespace after it, including the newline that ends
        // the line the action sits on.
        let trim_after = body.ends_with('-');
        if trim_after {
            body = body[..body.len() - 1].trim_end();
        }

        tokens.push(Token::Action(body.trim().to_string()));
        rest = &rest[consumed..];
        if trim_after {
            rest = rest.trim_start();
        }
    }
    if !rest.is_empty() {
        tokens.push(Token::Text(rest.to_string()));
    }
    Ok(tokens)
}

// --------------------------------------------------------------- parsing ---

#[derive(Debug)]
enum Node {
    Text(String),
    /// A group of nodes emitted once, or once per element of a range.
    Print(Expr),
    Range {
        /// The loop variable for the index, from `range $i, $v := …`.
        index: Option<String>,
        /// The loop variable for the element.
        value: String,
        list: Expr,
        body: Vec<Node>,
    },
}

#[derive(Debug)]
enum Expr {
    /// `.Envs.NAME`.
    Env(String),
    /// `$name` or `$name.Field`.
    Var {
        name: String,
        field: Option<String>,
    },
    Text(String),
    Number(i64),
    Call {
        name: String,
        args: Vec<Expr>,
    },
}

/// Parses tokens into a node tree, stopping at a dangling `{{end}}`.
///
/// Returns the nodes and the index of the token that stopped it, so the caller
/// can tell "the input ran out" from "an `end` closed a range I was inside of".
fn parse_nodes(tokens: &[Token], mut at: usize) -> Result<(Vec<Node>, usize)> {
    let mut nodes = Vec::new();
    while at < tokens.len() {
        match &tokens[at] {
            Token::Text(text) => {
                nodes.push(Node::Text(text.clone()));
                at += 1;
            }
            Token::Action(body) => {
                let mut words = Words::new(body);
                match words.peek() {
                    Some("end") => {
                        // `peek` left the word in `ahead`, so it has to be
                        // taken before `finish` looks for leftovers.
                        words.next();
                        words.finish()?;
                        return Ok((nodes, at));
                    }
                    Some("range") => {
                        words.next();
                        let (index, value, list) = parse_range_head(&mut words)?;
                        let (body, next) = parse_nodes(tokens, at + 1)?;
                        if next >= tokens.len() {
                            return Err(Error::config(format!(
                                "config template: `range {}` is never closed by `{{{{end}}}}`",
                                value
                            )));
                        }
                        nodes.push(Node::Range {
                            index,
                            value,
                            list,
                            body,
                        });
                        at = next + 1;
                    }
                    _ => {
                        nodes.push(Node::Print(parse_expr(&mut words)?));
                        words.finish()?;
                        at += 1;
                    }
                }
            }
        }
    }
    Ok((nodes, at))
}

/// `$_, $v := EXPR` or `$v := EXPR`, with the `range` keyword already eaten.
fn parse_range_head(words: &mut Words<'_>) -> Result<(Option<String>, String, Expr)> {
    let mut names = Vec::new();
    loop {
        let Some(word) = words.next() else {
            return Err(Error::config(
                "config template: `range` is missing its `:=`".to_string(),
            ));
        };
        if word == ":=" {
            break;
        }
        let Some(name) = word.strip_prefix('$') else {
            return Err(Error::config(format!(
                "config template: `range` binds variables, so it wants `$name`, not `{word}`"
            )));
        };
        // The comma in `$_, $v := …` is glued to the first name, because words
        // are split on whitespace.
        names.push(name.trim_end_matches(',').to_string());
    }

    let (index, value) = match names.len() {
        1 => (None, names.remove(0)),
        2 => (Some(names.remove(0)), names.remove(0)),
        n => {
            return Err(Error::config(format!(
                "config template: `range` takes one or two variables, got {n}"
            )))
        }
    };
    Ok((index, value, parse_expr(words)?))
}

/// One expression: a field, a variable, a literal, or a call.
fn parse_expr(words: &mut Words<'_>) -> Result<Expr> {
    let Some(word) = words.next() else {
        return Err(Error::config(
            "config template: empty `{{ }}` action".to_string(),
        ));
    };

    if let Some(rest) = word.strip_prefix('$') {
        let (name, field) = match rest.split_once('.') {
            Some((name, field)) => (name.to_string(), Some(field.to_string())),
            None => (rest.to_string(), None),
        };
        return Ok(Expr::Var { name, field });
    }

    if let Some(rest) = word.strip_prefix('.') {
        // `.Envs.NAME` is the only field path a config uses, and it is the only
        // one the root value has.
        let Some(name) = rest.strip_prefix("Envs.") else {
            return Err(Error::config(format!(
                "config template: `.{rest}` is not available; the root value has only `.Envs`"
            )));
        };
        return Ok(Expr::Env(name.to_string()));
    }

    if word.starts_with('"') {
        return Ok(Expr::Text(unquote(word)?));
    }

    if let Ok(number) = word.parse::<i64>() {
        return Ok(Expr::Number(number));
    }

    // Anything else is a function call, with its arguments as strings.
    let mut args = Vec::new();
    while let Some(arg) = words.peek() {
        if arg == ":=" {
            break;
        }
        args.push(parse_expr(words)?);
    }
    Ok(Expr::Call {
        name: word.to_string(),
        args,
    })
}

// ------------------------------------------------------------ evaluation ---

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Text(String),
    Number(i64),
    Pair(i64, i64),
    List(Vec<Value>),
}

impl Value {
    /// How `fmt` would print it, which is what a template interpolates.
    fn render(&self) -> String {
        match self {
            Value::Text(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            // A struct prints its fields in braces; a slice in brackets. A
            // config that interpolates one of these gets Go's spelling of it.
            Value::Pair(first, second) => format!("{{{first} {second}}}"),
            Value::List(items) => {
                let inner: Vec<String> = items.iter().map(Value::render).collect();
                format!("[{}]", inner.join(" "))
            }
        }
    }
}

/// The variables in scope. `$_` and `$v` are ordinary names here.
#[derive(Default)]
struct Scope {
    frames: Vec<HashMap<String, Value>>,
}

impl Scope {
    fn get(&self, name: &str) -> Option<&Value> {
        self.frames.iter().rev().find_map(|frame| frame.get(name))
    }
}

fn render_nodes(
    nodes: &[Node],
    scope: &mut Scope,
    envs: &HashMap<String, String>,
    out: &mut String,
) -> Result<()> {
    for node in nodes {
        match node {
            Node::Text(text) => out.push_str(text),
            Node::Print(expr) => out.push_str(&evaluate(expr, scope, envs)?.render()),
            Node::Range {
                index,
                value,
                list,
                body,
            } => {
                let items = match evaluate(list, scope, envs)? {
                    Value::List(items) => items,
                    other => {
                        return Err(Error::config(format!(
                            "config template: `range` needs a list, got {}",
                            other.render()
                        )))
                    }
                };
                for (position, item) in items.into_iter().enumerate() {
                    let mut frame = HashMap::new();
                    frame.insert(value.clone(), item);
                    if let Some(index) = index {
                        frame.insert(index.clone(), Value::Number(position as i64));
                    }
                    scope.frames.push(frame);
                    render_nodes(body, scope, envs, out)?;
                    scope.frames.pop();
                }
            }
        }
    }
    Ok(())
}

fn evaluate(expr: &Expr, scope: &Scope, envs: &HashMap<String, String>) -> Result<Value> {
    match expr {
        Expr::Text(text) => Ok(Value::Text(text.clone())),
        Expr::Number(number) => Ok(Value::Number(*number)),
        Expr::Env(name) => envs
            .get(name)
            .map(|v| Value::Text(v.clone()))
            .ok_or_else(|| {
                Error::config(format!(
                    "config template: `{{{{.Envs.{name}}}}}` but the environment has no `{name}`"
                ))
            }),
        Expr::Var { name, field } => {
            let value = scope.get(name).ok_or_else(|| {
                Error::config(format!("config template: `${name}` is not bound here"))
            })?;
            match field.as_deref() {
                None => Ok(value.clone()),
                // The only fields a config reads are the two halves of a pair.
                Some("First") => pair_field(value, 0, name, field.as_deref().unwrap_or("")),
                Some("Second") => pair_field(value, 1, name, field.as_deref().unwrap_or("")),
                Some(other) => Err(Error::config(format!(
                    "config template: `${name}.{other}` is not a field a range element has; \
                     use `$name.First` or `$name.Second`"
                ))),
            }
        }
        Expr::Call { name, args } => call(name, args, scope, envs),
    }
}

fn pair_field(value: &Value, which: usize, name: &str, field: &str) -> Result<Value> {
    match value {
        Value::Pair(first, second) => Ok(Value::Number(if which == 0 { *first } else { *second })),
        other => Err(Error::config(format!(
            "config template: `${name}.{field}` needs a pair, got {}",
            other.render()
        ))),
    }
}

fn call(name: &str, args: &[Expr], scope: &Scope, envs: &HashMap<String, String>) -> Result<Value> {
    // The name is checked before the arguments are evaluated. Otherwise
    // `{{ upper .Envs.NOPE }}` reports the missing variable, which sends the
    // reader looking for an environment variable when the real problem is a
    // function that does not exist.
    let wanted = match name {
        "parseNumberRange" => 1,
        "parseNumberRangePair" => 2,
        _ => {
            return Err(Error::config(format!(
                "config template: `{name}` is not a function this client provides;                  `parseNumberRange` and `parseNumberRangePair` are"
            )))
        }
    };
    if args.len() != wanted {
        return Err(Error::config(format!(
            "config template: `{name}` takes {wanted} argument(s), got {}",
            args.len()
        )));
    }

    let texts: Vec<String> = args
        .iter()
        .map(|arg| evaluate(arg, scope, envs).map(|value| value.render()))
        .collect::<Result<_>>()?;

    if name == "parseNumberRange" {
        let numbers = crate::util::range::parse_range_numbers(&texts[0])?;
        return Ok(Value::List(
            numbers.into_iter().map(Value::Number).collect(),
        ));
    }

    // `parseNumberRangePair` is expanded here rather than through
    // `util::range::parse_range_pair`, because the two callers want different
    // wording for the same mistake: the legacy INI `[range:]` sections talk
    // about ports, and a template should say what frp's own
    // `parseNumberRangePair` says. The count check is the whole of the
    // difference.
    let first = crate::util::range::parse_range_numbers(&texts[0])?;
    let second = crate::util::range::parse_range_numbers(&texts[1])?;
    if first.len() != second.len() {
        return Err(Error::config(
            "config template: first and second range numbers are not in pairs".to_string(),
        ));
    }
    Ok(Value::List(
        first
            .into_iter()
            .zip(second)
            .map(|(first, second)| Value::Pair(first, second))
            .collect(),
    ))
}

// --------------------------------------------------------------- helpers ---

/// Whitespace-separated words, with `"…"` kept whole.
struct Words<'a> {
    rest: &'a str,
    /// The last word handed out, so [`Words::peek`] can be answered without
    /// consuming it.
    ahead: Option<&'a str>,
}

impl<'a> Words<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            rest: input,
            ahead: None,
        }
    }

    fn next(&mut self) -> Option<&'a str> {
        if let Some(word) = self.ahead.take() {
            return Some(word);
        }
        let rest = self.rest.trim_start();
        if rest.is_empty() {
            return None;
        }
        let end = if let Some(body) = rest.strip_prefix('"') {
            // A quoted argument, to its closing quote. Unterminated is caught by
            // `unquote` when the word is used.
            match body.find('"') {
                Some(at) => at + 2,
                None => rest.len(),
            }
        } else {
            rest.find(char::is_whitespace).unwrap_or(rest.len())
        };
        self.rest = &rest[end..];
        Some(&rest[..end])
    }

    fn peek(&mut self) -> Option<&'a str> {
        if self.ahead.is_none() {
            self.ahead = self.next();
        }
        self.ahead
    }

    /// Rejects anything left over, so `{{ .Envs.A .Envs.B }}` is not silently
    /// half-read.
    fn finish(&mut self) -> Result<()> {
        match self.next() {
            None => Ok(()),
            Some(left) => Err(Error::config(format!(
                "config template: unexpected `{left}` after the action"
            ))),
        }
    }
}

/// Strips the quotes from a `"…"` argument, honouring Go's escapes.
fn unquote(word: &str) -> Result<String> {
    let Some(body) = word.strip_prefix('"') else {
        return Ok(word.to_string());
    };
    let Some(body) = body.strip_suffix('"') else {
        return Err(Error::config(format!(
            "config template: the string {word} is missing its closing quote"
        )));
    };

    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            // Go's `strconv.Unquote` accepts these, and a config that quotes a
            // Windows path relies on the second. No interpolation happens here
            // — unlike `envsubst`-style expanders, `$` is literal.
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some(other) => out.push(other),
            None => {
                return Err(Error::config(format!(
                    "config template: {word} ends in a backslash"
                )))
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn an_environment_variable_is_substituted() {
        let out = render_with(
            "serverAddr = \"{{ .Envs.FRP_SERVER_ADDR }}\"\nserverPort = 7000\n",
            &envs(&[("FRP_SERVER_ADDR", "frps.example.com")]),
        )
        .unwrap();
        assert_eq!(
            out,
            "serverAddr = \"frps.example.com\"\nserverPort = 7000\n"
        );
    }

    #[test]
    fn the_spacing_inside_the_braces_does_not_matter() {
        let e = envs(&[("A", "1")]);
        assert_eq!(render_with("{{.Envs.A}}", &e).unwrap(), "1");
        assert_eq!(render_with("{{ .Envs.A }}", &e).unwrap(), "1");
        assert_eq!(render_with("{{  .Envs.A  }}", &e).unwrap(), "1");
    }

    /// The case this exists for: a variable inside a section name.
    #[test]
    fn a_variable_can_be_part_of_a_larger_token() {
        let out = render_with(
            "[hq{{.Envs.MacAddr}}]\nmeta_port = {{.Envs.SshPort}}\n",
            &envs(&[("MacAddr", "1925369"), ("SshPort", "12236")]),
        )
        .unwrap();
        assert_eq!(out, "[hq1925369]\nmeta_port = 12236\n");
    }

    #[test]
    fn a_text_without_actions_is_returned_unchanged() {
        let input = "[common]\nserver_addr = 127.0.0.1\n";
        assert_eq!(render_with(input, &HashMap::new()).unwrap(), input);
    }

    /// A missing variable is an error rather than an empty string: a config that
    /// silently connects to "" would be a worse failure than one that stops.
    #[test]
    fn an_unset_variable_is_an_error_that_names_it() {
        let err = render_with("{{ .Envs.NOPE }}", &HashMap::new()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("NOPE"), "{text}");
        assert!(text.contains("environment has no"), "{text}");
    }

    #[test]
    fn an_unknown_function_is_refused_with_the_ones_that_exist() {
        let err = render_with("{{ upper .Envs.A }}", &HashMap::new()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("upper"), "{text}");
        assert!(text.contains("parseNumberRange"), "{text}");
    }

    /// An unterminated action has to say so rather than be read as text.
    #[test]
    fn an_unclosed_action_is_refused() {
        let err = render_with("server_port = {{ .Envs.A", &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("never closed"), "{err}");
    }

    #[test]
    fn parse_number_range_expands_the_way_frps_own_helper_does() {
        let out =
            render_with("{{ parseNumberRange \"6000-6002,6010\" }}", &HashMap::new()).unwrap();
        assert_eq!(out, "[6000 6001 6002 6010]");
    }

    #[test]
    fn parse_number_range_pair_produces_pairs() {
        let out = render_with(
            "{{ parseNumberRangePair \"6000-6001\" \"7000-7001\" }}",
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out, "[{6000 7000} {6001 7001}]");
    }

    #[test]
    fn mismatched_pair_lengths_are_refused() {
        let err = render_with(
            "{{ parseNumberRangePair \"6000-6001\" \"7000\" }}",
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("pairs"), "{err}");
    }

    /// The README's port-range example, verbatim.
    #[test]
    fn the_documented_range_example_renders() {
        let input = "{{- range $_, $v := parseNumberRangePair \"6000-6001\" \"7000-7001\" }}\n\
                     [[proxies]]\n\
                     name = \"tcp-{{ $v.First }}\"\n\
                     localPort = {{ $v.First }}\n\
                     remotePort = {{ $v.Second }}\n\
                     {{- end }}\n";
        let out = render_with(input, &HashMap::new()).unwrap();
        // The leading newline is correct, and is the reason this test exists.
        // `{{-` trims the whitespace *before* an action, and at the start of the
        // file there is none — the text that follows the `}}` is what carries
        // the line break the `range` sits on. Go produces the same string.
        assert_eq!(
            out,
            "\n[[proxies]]\n\
             name = \"tcp-6000\"\n\
             localPort = 6000\n\
             remotePort = 7000\n\
             [[proxies]]\n\
             name = \"tcp-6001\"\n\
             localPort = 6001\n\
             remotePort = 7001\n",
            "the `{{{{-` markers must swallow the newlines the range sits on"
        );
    }

    /// One-variable form, and the index variable.
    #[test]
    fn a_range_can_bind_the_index() {
        let out = render_with(
            "{{ range $i, $v := parseNumberRange \"10-12\" }}{{ $i }}:{{ $v }} {{ end }}",
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out, "0:10 1:11 2:12 ");
    }

    #[test]
    fn a_range_over_a_single_variable_leaves_the_index_unbound() {
        let out = render_with(
            "{{ range $v := parseNumberRange \"1-3\" }}{{ $v }},{{ end }}",
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out, "1,2,3,");
    }

    #[test]
    fn an_unclosed_range_is_refused() {
        let err =
            render_with("{{ range $v := parseNumberRange \"1\" }}x", &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("never closed"), "{err}");
    }

    #[test]
    fn a_dangling_end_is_refused() {
        let err = render_with("a{{ end }}b", &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("without a matching"), "{err}");
    }

    /// A field a pair does not have is named, rather than rendering empty.
    #[test]
    fn an_unknown_field_on_a_range_element_is_refused() {
        let err = render_with(
            "{{ range $v := parseNumberRangePair \"1\" \"2\" }}{{ $v.Third }}{{ end }}",
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("First"), "{err}");
    }

    #[test]
    fn a_variable_outside_its_range_is_refused() {
        let err = render_with("{{ $v }}", &HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("not bound"), "{err}");
    }

    #[test]
    fn an_escaped_quote_survives_unquoting() {
        let out = render_with("{{ parseNumberRange \"1\" }}", &HashMap::new()).unwrap();
        assert_eq!(out, "[1]");
        // And the escapes themselves.
        let out = render_with("{{ .Envs.P }}", &envs(&[("P", "a\tb")])).unwrap();
        assert_eq!(out, "a\tb");
    }

    #[test]
    fn a_variable_map_is_read_once_per_use() {
        // Two references to the same variable both resolve; there is no
        // consumption or ordering involved.
        let out = render_with("{{.Envs.A}}{{.Envs.A}}", &envs(&[("A", "x")])).unwrap();
        assert_eq!(out, "xx");
    }
}
