# Forced Execution

## Installation

- Clone the repository using `git clone -recurse-submodules`


### Build Soot

- `mvn install -DskipTests`
- Soot will then be installed as `4.5.0-SNAPSHOT-CUSTOM`

### Build FlowDroid

- `cd FlowDroid && mvn install -DskipTests`
- FlowDroid will then be installed as `2.13.0-SNAPSHOT-CUSTOM`

The forced execution contains of a static and a dynamic part. The static part is based on [TIRO](https://github.com/miwong/tiro/tree/master). The dynamic part is based on [Frida](https://frida.re/) and [uiautomator](https://github.com/xiaocong/uiautomator).
