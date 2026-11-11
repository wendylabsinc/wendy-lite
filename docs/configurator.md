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

## Why not just use Kconfig?

Kconfig alone cannot do what the configurator must do. There are three reasons.

### Some settings cannot depend on other settings

In ESP-IDF, some hardware settings are a Kconfig `choice`. For example, the
flash size is the choice `ESPTOOLPY_FLASHSIZE`, with the members
`ESPTOOLPY_FLASHSIZE_1MB` to `ESPTOOLPY_FLASHSIZE_128MB`. The PSRAM mode and
speed (`SPIRAM_MODE_*`, `SPIRAM_SPEED_*`) are choices too.

`select`, `imply`, `set` and `set default` have no effect on a choice member.
Thus a board option or a feature option cannot set the flash size. The other
possible methods have problems:

- A `default <member> if <option>` works only in a copy of the choice that
  Kconfig reads before the ESP-IDF definition. Also, if an `sdkconfig` file
  exists, the default does not change when the option changes. The old value
  stays.
- A `sdkconfig.defaults` file can set a choice member, but it is a static file.
  Its values cannot depend on other options.

### The Wendy CLI must show the menu

`wendy install` and `wendy run` must let the user select the configuration. The
Wendy CLI is a console application in Go. ESP-IDF shows Kconfig with
`menuconfig`, which is a Python tool. We know of no Go library that reads
Kconfig files and shows them as a menu.

### Users must see only a few options

A Wendy Lite build has more than 1,000 Kconfig options. Most of them are for
experts, or are internal to ESP-IDF and its components. `menuconfig` shows all
the ESP-IDF menus, and a project cannot hide them.

The configurator is a front end on top of Kconfig. It shows the user a small
set of options and hides the complexity. It then changes each selection into
the related Kconfig settings.

## Solution

One YAML file describes the configuration:
[configurator/master_conf.yaml](../configurator/master_conf.yaml). The file has
two parts:

- the **attributes**: the values that make a configuration
- the **rules**: the links between the attributes, and between the attributes
  and the Kconfig settings

The user gives the values of some attributes. The rules calculate the other
attributes. From all the attribute values, the configurator makes the
`sdkconfig` lines of the build.

### Attributes

An attribute is one value of the configuration. For example: the board, the
target chip, the flash size, or a feature such as Wendy Net. Each attribute has
a type (`string`, `size` or `boolean`) and can have a list of allowed values
(`enum`).

```yaml
attributes:
  board:
    type: string
    enum: [custom, seeed_xiao, esp32c6_devkit_c_1, ...]
  chip:
    type: string
    enum: [esp32c6, esp32c61, esp32c5, esp32p4, esp32s3, esp32s31]
  flash_size:
    type: size
    enum: [4MiB, 8MiB, 16MiB, 32MiB]
  app_type:
    type: string
    enum: [native, wasm]
  wendy_net:
    type: boolean
```

### Rules

A rule has a condition on the attributes. When the condition is true, the rule
can:

- set the values of other attributes (`set`)
- add Kconfig lines to the `sdkconfig` (`sdkconfig`)
- mark the combination of values as not allowed (`valid: false`). The
  configurator then stops with an error.

A rule can continue the rule before it with `else-if` or `else`, as in a
programming language.

For example, this rule sets the hardware of a board:

```yaml
  - if: board == "esp32c6_devkit_c_1"
    set:
      chip: esp32c6
      flash_size: 4MiB
      spram_size: 0
```

### Inputs and dependencies

The rules make a dependency graph. An attribute depends on the attributes in
the condition of each rule that sets it. In the example above, `chip`,
`flash_size` and `spram_size` depend on `board`.

- An attribute that no rule sets is an **input**. It depends on no other
  attribute, and the user must give its value. For example, `board` and
  `app_type` are inputs.
- An attribute that a rule sets is **derived**. The configurator calculates its
  value.

For some values, no rule sets a derived attribute. For example, no rule sets
the chip and the flash size of a custom board. Then the user must give these
values too. If a value that the `sdkconfig` lines need stays undefined, the
configurator lists the missing values and stops. If a rule sets a value that is
different from the value of the user or of another rule, the configurator stops
with an error.

The levels of [Basic principles](#basic-principles) are not written in the
file. They come from the rules: the board rules set the hardware attributes,
and the attributes of all levels can add Kconfig lines. An attribute can depend
on any other attribute, but the graph must not have a cycle.

### From the attributes to the sdkconfig

The configurator applies the rules in the order of the graph. Thus, when the
configurator reads a condition, the attributes in it have their final values.
Then the configurator collects the `sdkconfig` lines of all the rules with a
true condition, in the order of the file, and writes them to `sdkconfig.wendy`.

For example, these rules change the flash size into a member of the Kconfig
choice `ESPTOOLPY_FLASHSIZE`:

```yaml
  - if: flash_size == 4MiB
    sdkconfig: |
      CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y
  - if: flash_size == 8MiB
    sdkconfig: |
      CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y
```

`configure.py` then runs `idf.py set-target <chip>` with `sdkconfig.wendy` as
the last `SDKCONFIG_DEFAULTS` file. Thus its lines win over `sdkconfig.defaults`
and `sdkconfig.defaults.<chip>`. `sdkconfig.wendy` is a defaults file, but the
configurator makes it from the attributes. This solves the problem of
[the settings that cannot depend on other settings](#some-settings-cannot-depend-on-other-settings).

