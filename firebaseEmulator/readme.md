# Pre-requisite
(Make sure you to run all the commands in this page inside of firebaseEmulator/functions folder)    
```npm install```   
```npm install -g firebase-tools```

# Run
In 2 seperate terminals, run these:   
```npm run build:watch```   
```npm run emulator```

### Calling the firebase functions
This is only for firebase http request triggers.   
http://127.0.0.1:5001/demo-no-project/us-central1/FUNCTION_NAME   

(Can also be found in terminal after running emulator)


## Test cases 
(make sure emulator is running)   
```npm run test```

Or

```npm run emulatorAndTest``` (If you want to run both emulator and test in same terminal)


Troubleshooting
-Make sure to translate your ts code into js and that will be in lib folder. Sometimes, it gets bugged out somehow, if so delete your lib folder and rebuild again. 
-Check the translated index.js inside lib/functions/index.js matches with package.json, "main": "lib/functions/index.js"
-Debugger doesn't work?

Todo
-set up test cases for security rules, firebase functions