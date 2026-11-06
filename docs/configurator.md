# Configurator

Wendy Lite runs on different chips and boards, and a build can include different
features. The configurator defines how to select a configuration and how to
build the firmware from it.

## Goals

- **Build for different targets and boards.** The configurator builds Wendy Lite
  for a selected target and board, with a small set of options.
- **Work in all environments.** The configurator works in:
  - local development
  - CI
  - the Wendy CLI, for `wendy install` and `wendy run`
- **Keep the options few and well chosen.** The number of options must stay
  small. Users must be able to select the options themselves.
- **Save the configuration in the firmware.** The firmware stores the
  configuration that it was installed with. `wendy run` can then find how the
  target was installed.
- **Work with Kconfig.** Kconfig is the tool that we use for all firmware
  configuration. The configurator must work in combination with it.

## Basic principles

A configuration has four levels. Each level can depend on the levels before it.

### Level 0: board

The user selects a board from a list, or selects a custom board.

### Level 1: hardware

Level 1 describes the hardware.

- If the user selected a board from the list, the board defines all of level 1.
  The user has nothing to select.
- If the user selected a custom board, the user must select the hardware
  parameters. For example:
  - the target chip
  - the flash size
  - if the board has PSRAM, and its size

### Level 2: features

Level 2 contains the features that the user can enable or disable. For example:
WASM, Wendy Net, the Wendy Cloud tunnel and WendyCom over BLE.

A feature can depend on:

- other features. For example, the Wendy Cloud tunnel needs Wendy Cloud.
- the selections at level 0 and level 1. For example, WendyCom over BLE needs a
  board with a BLE radio.

### Level 3: Kconfig

Level 3 contains the Kconfig settings of the firmware. The selections at levels
0 to 2 must be able to change these settings, and a Kconfig setting must be able
to depend on these selections. For example:

- the flash size at level 1 sets `CONFIG_ESPTOOLPY_FLASHSIZE_8MB`
- WASM at level 2 sets `CONFIG_WENDY_WASM`
