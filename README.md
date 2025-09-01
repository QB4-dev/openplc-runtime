# openplc-runtime
OpenPLC Runtime v4 designed to run programs built on OpenPLC Editor v4

## 🛠️ Build Instructions

### 1. Build Application in the OpenPLC IDE
- First, build the application project on the **OpenPLC IDE**.  
- In the future, a **REST API** will be available to upload the generated files directly to the target in `path/to/project/build/OpenPLC Runtime/src/`.
- For now, copy the generated files manually into the `/core/generated` directory.

### 2. Generate Located Variables Header
- Use **XML2ST** to generate the `glueVars.c` file correctly.
   ```bash
   git clone https://github.com/Autonomy-Logic/xml2st.git
   cd xml2st
   git switch development
   xml2st --generate-gluevars /path/to/located_variables.h

- This header is required for successful compilation of `libplc.so`.

### 3. Compile Application into Shared Object
- With the generated files and `located_variables.h` in place, run the following command to generate libplc.so:
  ```bash
  bash scripts/compile.sh

- Run the following commands from the project root to build the runtime core:

   ```bash
   mkdir build
   cd build
   cmake ..
   make
