# Serverside Code Execution POC
Built for LLVM 19.1 - Windows x64 <br> <br>

One of the EASIEST ways to disrupt deobfuscation, is by removing the code to begin with. Arithmetic code is very simple to remove.
* We simply represent the code with a hash and the parameters.
* Connect to our websocket instance
* Send the hash and parameters off to the server
* Find the hash's opcode and its construction order (Prevent bruteforcing the sockets, requires code to execute in representation to its original order)
* Execute the opcode with the parameters
* Send it back to the client

You can even go one step further and do a proper VM with it to keep it out of scope, checking if the constant is ever consumed by anything that can't be server sided.<br>
This POC just hides the opcodes, as you can see by the screenshots, you can hide the constants too for any [Arith, IMM16/32/64] operations. <br>
The more you can push, the more you can keep information from being even recoverable. <br>
When dealing with DRMs in particular, there is realistically no reason to not serverside a lot of your code, anything that requires an internet connection might as well use a form of full blown serversided execution <br>

Before:<br>
<img width="707" height="454" alt="image" src="https://github.com/user-attachments/assets/31424262-5c0c-440a-8cbf-6fdc3cdb7b93" />
<br>
After:<br>
<img width="603" height="389" alt="image" src="https://github.com/user-attachments/assets/11c5ad5d-8874-4364-9f40-b6b56df23c8e" />
<br>
<img width="669" height="1020" alt="image" src="https://github.com/user-attachments/assets/9c7a4603-8f11-4606-b9b0-205ef0a83e37" />
<br>
As you can see, we just removed most of the arithmetics from the scope of the application. This is only a POC, you can hook the networking in its current state very easily. <br>

## The setup
This is a POC! DO NOT LET THIS REMOTELY NEAR YOUR PRODUCTION CODE! <br>
* Put ServerExecRuntime.cpp in your client code. 
```c
__attribute__((annotate("ServerExecCommunicator")))
```
* Use the "ServerExecCommunicator" annotation to mark your function that communicates with the server, this function becomes the caller for everything; any opcode we replace goes through this function. We need it marked to do that.
* Build your client with the LLVM pass
* The build process with make a SvxManifest.json
* You then use this in the server code to direct the client on each opcode it must execute.

## Annotations
```c
__attribute__((annotate("ServerExecCommunicator")))
``` 
* Marks your communication function that connects and handles sending websockets to the server
```c
__attribute__((annotate("serverexec")))
``` 
* Marks your function's body for serverside obfuscation

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
