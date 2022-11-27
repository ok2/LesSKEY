#[derive(Debug)]
struct LKRead {
  rl: Editor::<()>,
  prompt: String,
  state: Rc<RefCell<LK>>,
  cmd: String,
}

#[derive(Debug)]
struct LKEval<'a> {
  cmd: Command<'a>,
  state: Rc<RefCell<LK>>,
}

#[derive(Debug)]
struct LKPrint {
  out: Vec<String>,
  quit: bool,
  // state: Rc<RefCell<LK>>,
}

impl LKRead {
  fn new(rl: Editor::<()>, prompt: String, state: Rc<RefCell<LK>>) -> Self {
     Self { rl, prompt, state, cmd: "".to_string() }
  }

  fn read(&mut self) -> LKEval {
    self.cmd = match self.rl.readline(&*self.prompt) {
      Ok(str) => str,
      Err(err) => return LKEval::new(Command::Error(LKErr::ReadError(err.to_string())), self.state.clone()),
    };
    match command_parser::cmd(self.cmd.as_str()) {
      Ok(cmd) => LKEval::new(cmd, self.state.clone()),
      Err(err) => LKEval::new(Command::Error(LKErr::PegParseError(err)), self.state.clone()),
    }
  }

  fn refresh(&mut self) {

  }

  fn quit(&mut self) {

  }
}

impl<'a> LKEval<'a> {
  fn new(cmd: Command<'a>, state: Rc<RefCell<LK>>) -> Self { Self { cmd, state } }

  fn eval(&mut self) -> LKPrint {
    let mut out: Vec<String> = vec![];
    let mut quit: bool = false;

    match &self.cmd {
      Command::Quit => {
        out.push("Bye!".to_string());
        quit = true;
      },
      Command::Ls => {
        for (_, name) in &self.state.borrow().db {
          let pw = name.borrow();
          let prefix = match pw.prefix.as_ref() { Some(s) => format!("{} ", s), None => "".to_string() };
          let length = match pw.length { Some(l) => format!("{}", l), None => "".to_string() };
          let comment = match pw.comment.as_ref() { Some(s) => format!(" {}", s), None => "".to_string() };
          let parent = match &pw.parent { Some(s) => format!(" ^{}", s.borrow().name), None => "".to_string() };
          out.push(format!("{}{} {}{} {} {}{}{}", prefix, pw.name, length, pw.mode, pw.seq, pw.date, comment, parent));
        }
      },
      Command::Add(name) => {
        if self.state.borrow().db.get(&name.borrow().name).is_some() {
          out.push("error: password already exist".to_string());
        } else {
          self.state.borrow_mut().db.insert(name.borrow().name.clone(), name.clone());
          self.state.borrow().fix_hierarchy();
        }
      },
      Command::Help => {
        out.push("HELP".to_string());
      },
      Command::Mv(name, folder) => {
        for (_, tmp) in &self.state.borrow().db {
          if *tmp.borrow().name == *name {
            if folder == "/" { tmp.borrow_mut().parent = None }
            else {
              for (_, fld) in &self.state.borrow().db {
                if *fld.borrow().name == *folder {
                  tmp.borrow_mut().parent = Some(fld.clone());
                  break;
                }
              }
            }
            break;
          }
        }
      },
      Command::Error(err) => {
        match err {
          LKErr::PegParseError(e) => { out.push(e.to_string()) },
          LKErr::ReadError(e) => { out.push(e.to_string()) },
          LKErr::Error(e) => { out.push(format!("error: {}", e.to_string())) },
          _ => out.push(format!("error: {:?}", err)),
        }
      }
    }

    LKPrint::new(out, quit)
  }
}

impl LKPrint {
    fn new(out: Vec<String>, quit: bool) -> Self { Self { out, quit } }

    fn print(&mut self) -> bool {
        for line in &self.out {
            println!("{}", line);
        }
        return !self.quit;
    }
}
