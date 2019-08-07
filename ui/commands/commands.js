// Sshwifty - A Web SSH client
//
// Copyright (C) 2019 Rui NI <nirui@gmx.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import Exception from "./exception.js";
import * as stream from "../stream/streams.js";
import * as subscribe from "../stream/subscribe.js";

export const NEXT_PROMPT = 1;
export const NEXT_WAIT = 2;
export const NEXT_DONE = 3;

export class Result {
  /**
   * constructor
   *
   * @param {string} name Result type
   * @param {Info} info Result info
   * @param {object} control Result controller
   */
  constructor(name, info, control) {
    this.name = name;
    this.info = info;
    this.control = control;
  }
}

class Done {
  /**
   * constructor
   *
   * @param {object} data Step data
   *
   */
  constructor(data) {
    this.s = !!data.success;
    this.d = data.successData;
    this.errorTitle = data.errorTitle;
    this.errorMessage = data.errorMessage;
  }

  /**
   * Return the error of current Done
   *
   * @returns {string} title
   *
   */
  error() {
    return this.errorTitle;
  }

  /**
   * Return the error message of current Done
   *
   * @returns {string} message
   *
   */
  message() {
    return this.errorMessage;
  }

  /**
   * Returns whether or not current Done is representing a success
   *
   * @returns {boolean} True when success, false otherwise
   */
  success() {
    return this.s;
  }

  /**
   * Returns final data
   *
   * @returns {Result} Successful result
   */
  data() {
    return this.d;
  }
}

class Wait {
  /**
   * constructor
   *
   * @param {object} data Step data
   *
   */
  constructor(data) {
    this.t = data.title;
    this.m = data.message;
  }

  /**
   * Return the title of current Wait
   *
   * @returns {string} title
   *
   */
  title() {
    return this.t;
  }

  /**
   * Return the message of current Wait
   *
   * @returns {string} message
   *
   */
  message() {
    return this.m;
  }
}

const defField = {
  name: "",
  description: "",
  type: "",
  value: "",
  example: "",
  verify(v) {
    return "OK";
  }
};

/**
 * Create a Prompt field
 *
 * @param {object} def Field default value
 * @param {object} f Field value
 *
 * @returns {object} Field data
 *
 * @throws {Exception} When input field is invalid
 *
 */
export function field(def, f) {
  let n = {};

  for (let i in def) {
    n[i] = def[i];
  }

  for (let i in f) {
    if (typeof n[i] !== typeof f[i]) {
      throw new Exception(
        'Field data type for "' +
          i +
          '" was not unmatched. Expecting "' +
          typeof def[i] +
          '", got "' +
          typeof f[i] +
          '" instead'
      );
    }

    n[i] = f[i];
  }

  if (!n["name"]) {
    throw new Exception('Field "name" must be specified');
  }

  return n;
}

/**
 * Build a group of field value
 *
 * @param {object} definitions Definition of a group of fields
 * @param {array<object>} fs Data of the field group
 *
 * @returns {array<object>} Result fields
 *
 * @throws {Exception} When input field is invalid
 *
 */
export function fields(definitions, fs) {
  let fss = [];

  for (let i in fs) {
    if (!fs[i]["name"]) {
      throw new Exception('Field "name" must be specified');
    }

    if (!definitions[fs[i].name]) {
      throw new Exception('Undefined field "' + fs[i].name + '"');
    }

    fss.push(field(definitions[fs[i].name], fs[i]));
  }

  return fss;
}

class Prompt {
  /**
   * constructor
   *
   * @param {object} data Step data
   *
   * @throws {Exception} If the field verify is not a function while
   *                               not null
   */
  constructor(data) {
    this.t = data.title;
    this.m = data.message;
    this.a = data.actionText;
    this.r = data.respond;
    this.c = data.cancel;

    this.i = [];
    this.f = {};

    for (let i in data.inputs) {
      let f = field(defField, data.inputs[i]);

      this.i.push(f);

      this.f[data.inputs[i].name.toLowerCase()] = {
        value: f.value,
        verify: f.verify
      };
    }
  }

  /**
   * Return the title of current Prompt
   *
   * @returns {string} title
   *
   */
  title() {
    return this.t;
  }

  /**
   * Return the message of current Prompt
   *
   * @returns {string} message
   *
   */
  message() {
    return this.m;
  }

  /**
   * Return the input field of current prompt
   *
   * @returns {array} Input fields
   *
   */
  inputs() {
    let inputs = [];

    for (let i in this.i) {
      inputs.push(this.i[i]);
    }

    return inputs;
  }

  /**
   * Returns the name of the action
   *
   * @returns {string} Action name
   *
   */
  actionText() {
    return this.a;
  }

  /**
   * Receive the submit of current prompt
   *
   * @param {object} inputs Input value
   *
   * @returns {any} The result of the step responder
   *
   * @throws {Exception} When the field is undefined or invalid
   *
   */
  submit(inputs) {
    let fields = {};

    for (let i in this.f) {
      fields[i] = this.f[i].value;
    }

    for (let i in inputs) {
      let k = i.toLowerCase();

      if (typeof fields[k] === "undefined") {
        throw new Exception('Field "' + k + '" is undefined');
      }

      try {
        this.f[k].verify(inputs[i]);
      } catch (e) {
        throw new Exception('Field "' + k + '" is invalid: ' + e);
      }

      fields[k] = inputs[i];
    }

    return this.r(fields);
  }

  /**
   * Cancel current wait operation
   *
   */
  cancel() {
    return this.c();
  }
}

/**
 * Create a Wizard step
 *
 * @param {string} type Step type
 * @param {object} data Step data
 *
 * @returns {object} Step data
 *
 */
function next(type, data) {
  return {
    type() {
      return type;
    },
    data() {
      return data;
    }
  };
}

/**
 * Create data for a Done step of the wizard
 *
 * @param {boolean} success
 * @param {Success} successData
 * @param {string} errorTitle
 * @param {string} errorMessage
 *
 * @returns {object} Done step data
 *
 */
export function done(success, successData, errorTitle, errorMessage) {
  return next(NEXT_DONE, {
    success: success,
    successData: successData,
    errorTitle: errorTitle,
    errorMessage: errorMessage
  });
}

/**
 * Create data for a Wait step of the wizard
 *
 * @param {string} title Waiter title
 * @param {message} message Waiter message
 *
 * @returns {object} Done step data
 *
 */
export function wait(title, message) {
  return next(NEXT_WAIT, {
    title: title,
    message: message
  });
}

/**
 * Create data for a Prompt step of the wizard
 *
 * @param {string} title Title of the prompt
 * @param {string} message Message of the prompt
 * @param {string} actionText Text of the action (button)
 * @param {function} respond Respond callback
 * @param {function} cancel cancel handler
 * @param  {object} inputs Input field objects
 *
 * @returns {object} Prompt step data
 *
 */
export function prompt(title, message, actionText, respond, cancel, inputs) {
  return next(NEXT_PROMPT, {
    title: title,
    message: message,
    actionText: actionText,
    inputs: inputs,
    respond: respond,
    cancel: cancel
  });
}

class Next {
  /**
   * constructor
   *
   * @param {object} data Step data
   */
  constructor(data) {
    this.t = data.type();
    this.d = data.data();
  }

  /**
   * Return step type
   *
   * @returns {string} Step type
   */
  type() {
    return this.t;
  }

  /**
   * Return step data
   *
   * @returns {Done|Prompt} Step data
   *
   * @throws {Exception} When the step type is unknown
   *
   */
  data() {
    switch (this.type()) {
      case NEXT_PROMPT:
        return new Prompt(this.d);

      case NEXT_WAIT:
        return new Wait(this.d);

      case NEXT_DONE:
        return new Done(this.d);

      default:
        throw new Exception("Unknown data type");
    }
  }
}

class Wizard {
  /**
   * constructor
   *
   * @param {function} builder Command builder
   * @param {subscribe.Subscribe} subs Wizard step subscriber
   *
   */
  constructor(built, subs) {
    this.built = built;
    this.subs = subs;
    this.closed = false;
  }

  /**
   * Return the Next step
   *
   * @returns {Next} Next step
   *
   * @throws {Exception} When wizard is closed
   *
   */
  async next() {
    if (this.closed) {
      throw new Exception("Wizard already closed, no next step is available");
    }

    let n = await this.subs.subscribe();

    if (n.type() === NEXT_DONE) {
      this.close();
    }

    return new Next(n);
  }

  /**
   * Return whether or not the command is started
   *
   * @returns {boolean} True when the command already started, false otherwise
   *
   */
  started() {
    return this.built.started();
  }

  /**
   * Close current wizard
   *
   * @returns {any} Close result
   *
   */
  close() {
    if (this.closed) {
      return;
    }

    this.closed = true;

    return this.built.close();
  }
}

export class Info {
  /**
   * constructor
   *
   * @param {Builder} info Builder info
   *
   */
  constructor(info) {
    this.type = info.name();
    this.info = info.description();
    this.tcolor = info.color();
  }

  /**
   * Return command name
   *
   * @returns {string} Command name
   *
   */
  name() {
    return this.type;
  }

  /**
   * Return command description
   *
   * @returns {string} Command description
   *
   */
  description() {
    return this.info;
  }

  /**
   * Return the theme color of the command
   *
   * @returns {string} Command name
   *
   */
  color() {
    return this.tcolor;
  }
}

class Builder {
  /**
   * constructor
   *
   * @param {object} command Command builder
   *
   */
  constructor(command) {
    this.cid = command.id();
    this.builder = (n, i, r, u, y, x) => {
      return command.builder(n, i, r, u, y, x);
    };
    this.launchCmd = (n, i, r, u, y, x) => {
      return command.launch(n, i, r, u, y, x);
    };
    this.launcherCmd = c => {
      return command.launcher(c);
    };
    this.type = command.name();
    this.info = command.description();
    this.tcolor = command.color();
  }

  /**
   * Return the command ID
   *
   * @returns {number} Command ID
   *
   */
  id() {
    return this.cid;
  }

  /**
   * Return command name
   *
   * @returns {string} Command name
   *
   */
  name() {
    return this.type;
  }

  /**
   * Return command description
   *
   * @returns {string} Command description
   *
   */
  description() {
    return this.info;
  }

  /**
   * Return the theme color of the command
   *
   * @returns {string} Command name
   *
   */
  color() {
    return this.tcolor;
  }

  /**
   * Build command wizard
   *
   * @param {stream.Streams} streams
   * @param {controls.Controls} controls
   * @param {history.History} history
   * @param {object} config
   *
   * @returns {Wizard} Command wizard
   *
   */
  build(streams, controls, history, config) {
    let subs = new subscribe.Subscribe();

    return new Wizard(
      this.builder(new Info(this), config, streams, subs, controls, history),
      subs
    );
  }

  /**
   * Launch command wizard out of given launcher string
   *
   * @param {stream.Streams} streams
   * @param {controls.Controls} controls
   * @param {history.History} history
   * @param {string} launcher Launcher format
   *
   * @returns {Wizard} Command wizard
   *
   */
  launch(streams, controls, history, launcher) {
    let subs = new subscribe.Subscribe();

    return new Wizard(
      this.launchCmd(
        new Info(this),
        launcher,
        streams,
        subs,
        controls,
        history
      ),
      subs
    );
  }

  /**
   * Build launcher string out of given config
   *
   * @param {object} config Configuration object
   *
   * @return {string} Launcher string
   */
  launcher(config) {
    return this.name() + ":" + this.launcherCmd(config);
  }
}

export class Commands {
  /**
   * constructor
   *
   * @param {[]object} commands Command array
   *
   */
  constructor(commands) {
    this.commands = [];

    for (let i in commands) {
      this.commands.push(new Builder(commands[i]));
    }
  }

  /**
   * Return all commands
   *
   * @returns {[]Builder} A group of command
   *
   */
  all() {
    return this.commands;
  }

  /**
   * Select one command
   *
   * @param {number} id Command ID
   *
   * @returns {Builder} Command builder
   *
   */
  select(id) {
    return this.commands[id];
  }
}