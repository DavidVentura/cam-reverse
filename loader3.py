#!/bin/env python
import frida

# Define the JavaScript code to hook System.loadLibrary()
js_code = """
const System = Java.use('java.lang.System');

System.loadLibrary.implementation = function(libraryName) {
    console.log('Loading library: ' + libraryName);
    // You can add your custom logic here before calling the original function.
    return this.loadLibrary(libraryName);
};
"""
target_package_name = "com.ysxlite.cam"
shared_library_name = "vdp.so"
native_function_name = "p2p_read"
js_code = open('asd.js').read()
def on_message(m, _data):
    print('got', m, _data)

def main():
    # Replace 'com.example.targetapp' with the actual package name of your target app.
    app_id = "com.ysxlite.cam"
    target_app_package = 'com.ysxlite.cam'
    target_app_package = 'YsxLite'

    device = frida.get_usb_device()
    session = device.attach(target_app_package)
    #pid = device.spawn([app_id])
    #print(pid)
    #session = device.attach(pid)
    # Attach to the target app
    print(session)

    # Create a script and load the JavaScript code
    script = session.create_script(js_code)

    script.on('message', on_message)
    script.load()
    # device.resume(target_app_package)

    # Keep the script running to continue monitoring the app
    input("Press Enter to stop...")

if __name__ == '__main__':
    main()

