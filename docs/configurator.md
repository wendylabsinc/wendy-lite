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
[master_config.yaml](../master_config.yaml), in the repository root. The file has
two parts:

- the **attributes**: the values that make a configuration
- the **rules**: the links between the attributes, and between the attributes
  and the Kconfig settings

The user gives the values of some attributes. The rules calculate the other
attributes. From all the attribute values, the configurator makes the
`sdkconfig` lines of the build.

The code of the configurator is in [tools/configurator/](../tools/configurator/).
To configure the build, run [tools/configure.py](../tools/configure.py) in the
repository root, for example `tools/configure.py board=seeed_xiao app_type=native`.
`tools/configurator/solve.py` takes the same arguments, but it only writes
`sdkconfig.wendy`.

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
  idf_version:
    type: string
    enum: ["6.0.3", "6.1"]
  idf_preview:
    type: boolean
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

The first line of `sdkconfig.wendy` is `CONFIG_WENDY_BUILD_PROFILE`. It
contains the input values (the values file and the `NAME=VALUE` arguments) as
flat YAML, in the order of the attributes in `master_config.yaml`. The values
that the rules set are not in it. Kconfig cannot store a newline, so the
2 characters `\n` (backslash, n) separate the lines. In `sdkconfig.wendy`,
Kconfig escapes the backslash:

```text
CONFIG_WENDY_BUILD_PROFILE="board: m5_stamp_s3\\napp_type: native"
```

The firmware gets the string `board: m5_stamp_s3\napp_type: native`, with the
2 characters `\n` between the lines. When `\n` is changed into a newline, the
text is a valid values file.

`configure.py` then runs `idf.py set-target <chip>` with `sdkconfig.wendy` as
the last `SDKCONFIG_DEFAULTS` file. Thus its lines win over `sdkconfig.defaults`
and `sdkconfig.defaults.<chip>`. `sdkconfig.wendy` is a defaults file, but the
configurator makes it from the attributes. This solves the problem of
[the settings that cannot depend on other settings](#some-settings-cannot-depend-on-other-settings).

### ESP-IDF version

The attribute `idf_version` gives the ESP-IDF version that the build needs. It
is 6.0.3, except for the ESP32-S31, which needs ESP-IDF 6.1. ESP-IDF 6.1
supports the ESP32-S31 only as a preview target, so the attribute
`idf_preview` is true for it:

```yaml
  - if: chip == "esp32s31"
    set:
      idf_version: "6.1"
      idf_preview: true
  - else:
    set:
      idf_version: "6.0.3"
      idf_preview: false
```

When `idf_preview` is true, `configure.py` adds `--preview` to `idf.py`.

Before `idf.py set-target`, `configure.py` reads the version of the active
ESP-IDF from `$IDF_PATH/tools/cmake/version.cmake`. If it is not the version of
`idf_version`, `configure.py` stops with an error and does not run `idf.py`.
The versions must be equal. A missing number is 0, as in the ESP-IDF tags:
`6.1` is 6.1.0. For now, `configure.py` does not select ESP-IDF. The user must
activate the correct version first.

## Questions in the Wendy CLI

`wendy install` and `wendy run` ask the user for the input values. The Go
configurator of the Wendy CLI (`go/internal/cli/litebuild` in WendyOS) reads
the same `master_config.yaml`. For the same input values, it gives the same
`sdkconfig` lines as `solve.py`.

### Display

The section `display` of `master_config.yaml` tells the Wendy CLI how to ask the
questions. The Python configurator does not read it. Each entry is the name of
an attribute, with these keys. All the keys are optional.

- `title`: the question title. The default is the attribute name.
- `help`: a line under the question.
- `priority`: the order of the questions, smaller first. See
  [Order of the questions](#order-of-the-questions).
- `default`: the preselected answer. The CLI uses it only when it is allowed,
  and when the user has no allowed answer from the last run. See
  [Previous answers](#previous-answers).
- `values`: the label of each enum value, or of `true` and `false`.

```yaml
display:
  board:
    title: Board
    priority: 1
    values:
      seeed_xiao: Seeed Studio XIAO ESP32S3
```

The type of the attribute gives the type of the question: a list for an enum,
yes or no for a boolean, and a text for an attribute without enum.

An attribute that is not in `display` is internal, for example `spram_size`
or `idf_version`. The CLI never shows an internal attribute. An entry with no
keys (`spram_size:` alone) makes the attribute visible. When an internal
attribute has only one allowed value, the CLI takes it and does not show it.
When the CLI must ask for an internal attribute, it stops with an error: the
attribute must be added to `display`.

### Order of the questions

The question order is an order of the graph: an attribute comes after the
attributes that it depends on. The attributes are sorted by `priority`, then
in the order of `attributes`. An attribute without priority comes after the
others. Each attribute takes the attributes that it depends on with it, before
it.

The CLI goes through the attributes in this order. At each attribute, it
applies the rules that set the attribute, as in
[From the attributes to the sdkconfig](#from-the-attributes-to-the-sdkconfig).
Then:

- If a rule set the attribute, the CLI shows the value of a visible attribute.
  There is no question.
- If the `sdkconfig` lines, the chip, `idf_version` and `idf_preview` do not
  need the attribute, directly or through the rules, the CLI skips it. The
  attribute stays undefined. These are the values that `configure.py` needs.
- Else the CLI finds the allowed answers. If only one answer is allowed, the
  CLI takes it, shows it for a visible attribute and asks no question. If more
  answers are allowed, the CLI asks the question and shows only the allowed
  answers. For an internal attribute, this is an error.

### Allowed answers

An answer is allowed when the next questions have answers that give an allowed
configuration: no conflict, no `valid: false` rule with a true condition, and
no missing value. These are the checks of `solve.py`. The CLI finds the
allowed answers with a search over the values of the next questions. For an
attribute without enum, the search uses one value of each set of values that
the conditions cannot tell apart.

The CLI applies a rule only when all the attributes in its condition have
their final values. Thus a condition such as `!wendy_net` is not true before
the user answers the `wendy_net` question.

The answers and the only allowed values are the input values. They go to
`CONFIG_WENDY_BUILD_PROFILE`. `solve.py` with the same values as `NAME=VALUE`
arguments gives the same `sdkconfig.wendy`.

### Previous answers

The CLI keeps the input values of the last run in its cache
(`wendy-lite-build/answers.json`). The next run preselects the previous answer
of each question when it is allowed, else `display.default`. An input value of
an older run stays in the file until a run answers the same question again.
When `master_config.yaml` changes, the CLI ignores the attributes and the values
that are no longer valid.
