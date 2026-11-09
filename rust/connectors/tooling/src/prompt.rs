// SPDX-License-Identifier: Apache-2.0
//! Talking to the user: menus that show unavailable options with the reason, text and yes/no
//! questions. Every question has a flag, and without a terminal the question is refused with
//! that flag named.

use std::io::{BufRead, IsTerminal, StdinLock, Stdout, Write};

pub struct MenuOption<T> {
    pub label: String,
    pub value: T,
    /// The reason the option can't be picked here, or `None` when it can.
    pub unavailable: Option<String>,
}

impl<T> MenuOption<T> {
    pub fn available(label: impl Into<String>, value: T) -> Self {
        MenuOption {
            label: label.into(),
            value,
            unavailable: None,
        }
    }

    pub fn unavailable(label: impl Into<String>, value: T, reason: impl Into<String>) -> Self {
        MenuOption {
            label: label.into(),
            value,
            unavailable: Some(reason.into()),
        }
    }
}

/// The steps a command takes, shown as "This will:" before it asks to continue.
#[derive(Debug, Default)]
pub struct Plan {
    steps: Vec<String>,
}

impl Plan {
    pub fn add_step(&mut self, step: impl Into<String>) {
        self.steps.push(step.into());
    }
}

pub struct Prompt<R = StdinLock<'static>, W = Stdout> {
    input: R,
    output: W,
    interactive: bool,
}

impl Prompt {
    /// Asks on stdin and stdout. Questions are refused when stdin is not a terminal.
    pub fn terminal() -> Prompt {
        Prompt {
            interactive: std::io::stdin().is_terminal(),
            input: std::io::stdin().lock(),
            output: std::io::stdout(),
        }
    }
}

impl<R: BufRead, W: Write> Prompt<R, W> {
    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    pub fn say(&mut self, text: &str) -> Result<(), PromptError> {
        Ok(writeln!(self.output, "{text}")?)
    }

    pub fn warn(&mut self, text: &str) -> Result<(), PromptError> {
        Ok(writeln!(self.output, "warning: {text}")?)
    }

    /// Shows every option, numbered, and returns the value picked. Picking an unavailable
    /// option repeats its reason and asks again.
    pub fn choose<'a, T>(
        &mut self,
        question: &str,
        flag: &str,
        options: &'a [MenuOption<T>],
    ) -> Result<&'a T, PromptError> {
        self.refuse_without_terminal(question, flag)?;
        self.say(question)?;
        for (number, option) in (1..).zip(options) {
            let line = match &option.unavailable {
                None => format!("  {number}) {}", option.label),
                Some(reason) => format!("  {number}) {} (not available: {reason})", option.label),
            };
            self.say(&line)?;
        }
        loop {
            let answer = self.read_answer(&format!("Choose 1-{}: ", options.len()), question)?;
            let picked = answer
                .parse::<usize>()
                .ok()
                .and_then(|number| options.get(number.checked_sub(1)?));
            match picked {
                Some(MenuOption {
                    unavailable: None,
                    value,
                    ..
                }) => return Ok(value),
                Some(MenuOption {
                    unavailable: Some(reason),
                    label,
                    ..
                }) => self.say(&format!("{label} is not available: {reason}"))?,
                None => self.say(&format!("{answer:?} is not one of the options"))?,
            }
        }
    }

    /// Asks for text. An empty answer gives `default`, or asks again when there is none.
    pub fn ask(
        &mut self,
        question: &str,
        flag: &str,
        default: Option<&str>,
    ) -> Result<String, PromptError> {
        self.refuse_without_terminal(question, flag)?;
        let shown = match default {
            Some(default) => format!("{question} [{default}]: "),
            None => format!("{question}: "),
        };
        loop {
            let answer = self.read_answer(&shown, question)?;
            match (answer.is_empty(), default) {
                (false, _) => return Ok(answer),
                (true, Some(default)) => return Ok(default.to_owned()),
                (true, None) => self.say("an answer is needed")?,
            }
        }
    }

    pub fn ask_yes_no(
        &mut self,
        question: &str,
        flag: &str,
        default: bool,
    ) -> Result<bool, PromptError> {
        self.refuse_without_terminal(question, flag)?;
        let shown = format!("{question} [{}] ", if default { "Y/n" } else { "y/N" });
        loop {
            match self
                .read_answer(&shown, question)?
                .to_ascii_lowercase()
                .as_str()
            {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => self.say("answer y or n")?,
            }
        }
    }

    /// Shows `plan` and asks to continue. With `yes` the plan is shown and accepted.
    pub fn confirm(&mut self, plan: &Plan, yes: bool) -> Result<bool, PromptError> {
        self.say("This will:")?;
        for step in &plan.steps {
            self.say(&format!("  - {step}"))?;
        }
        if yes {
            return Ok(true);
        }
        self.ask_yes_no("Continue?", "--yes", true)
    }

    fn refuse_without_terminal(&self, question: &str, flag: &str) -> Result<(), PromptError> {
        if self.interactive {
            return Ok(());
        }
        Err(PromptError::NoTerminal {
            question: question.to_owned(),
            flag: flag.to_owned(),
        })
    }

    fn read_answer(&mut self, shown: &str, question: &str) -> Result<String, PromptError> {
        write!(self.output, "{shown}")?;
        self.output.flush()?;
        let mut line = String::new();
        if self.input.read_line(&mut line)? == 0 {
            return Err(PromptError::Closed(question.to_owned()));
        }
        Ok(line.trim().to_owned())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    #[error("no terminal to ask {question:?}: pass {flag}")]
    NoTerminal { question: String, flag: String },
    #[error("input ended before {0:?} was answered")]
    Closed(String),
    #[error("talking to the terminal")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn answering(input: &str) -> Prompt<Cursor<Vec<u8>>, Vec<u8>> {
        Prompt {
            input: Cursor::new(input.as_bytes().to_vec()),
            output: Vec::new(),
            interactive: true,
        }
    }

    fn shown(prompt: &Prompt<Cursor<Vec<u8>>, Vec<u8>>) -> String {
        String::from_utf8(prompt.output.clone()).unwrap()
    }

    fn folders() -> [MenuOption<&'static str>; 3] {
        [
            MenuOption::available("/opt/ajar-connectors", "opt"),
            MenuOption::unavailable("~/.ajar-connectors", "home", "running as root"),
            MenuOption::available("another folder", "other"),
        ]
    }

    #[test]
    fn menu_shows_unavailable_options_and_repeats_the_reason_when_picked() {
        let mut prompt = answering("2\n7\n3\n");
        let options = folders();
        let picked = prompt.choose("Where?", "--dir", &options).unwrap();
        assert_eq!(*picked, "other");
        let shown = shown(&prompt);
        assert!(
            shown.contains("2) ~/.ajar-connectors (not available: running as root)"),
            "{shown}"
        );
        assert!(
            shown.contains("~/.ajar-connectors is not available: running as root"),
            "{shown}"
        );
        assert!(shown.contains("\"7\" is not one of the options"), "{shown}");
    }

    #[test]
    fn question_without_terminal_names_the_flag() {
        let mut prompt = answering("1\n");
        prompt.interactive = false;
        let err = prompt.choose("Where?", "--dir", &folders()).unwrap_err();
        assert_eq!(err.to_string(), "no terminal to ask \"Where?\": pass --dir");
    }

    #[test]
    fn empty_answer_takes_the_default() {
        let mut prompt = answering("\n\n");
        assert_eq!(
            prompt.ask("Name", "--name", Some("radar-1")).unwrap(),
            "radar-1"
        );
        assert!(!prompt.ask_yes_no("Delete it?", "--delete", false).unwrap());
    }

    #[test]
    fn ended_input_is_an_error() {
        let mut prompt = answering("");
        let err = prompt.ask("Name", "--name", None).unwrap_err();
        assert!(matches!(err, PromptError::Closed(_)), "{err}");
    }

    #[test]
    fn plan_is_shown_and_yes_skips_the_question() {
        let mut plan = Plan::default();
        plan.add_step("create /opt/ajar-connectors");
        let mut prompt = answering("");
        prompt.interactive = false;
        assert!(prompt.confirm(&plan, true).unwrap());
        assert_eq!(
            shown(&prompt),
            "This will:\n  - create /opt/ajar-connectors\n"
        );

        let mut prompt = answering("n\n");
        assert!(!prompt.confirm(&plan, false).unwrap());
    }
}
