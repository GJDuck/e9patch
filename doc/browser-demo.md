E9Tool/E9Patch Web Browser Guide
================================

This is a short demo for instrumenting modern web browsers using
E9Tool/E9Patch.

---
## Instrument Firefox

Modern versions of Firefox should be straightforward to instrument.
Below is a basic example:

0. Install E9Tool/E9Patch:

   * [https://github.com/GJDuck/e9patch/releases](https://github.com/GJDuck/e9patch/releases)

1. Download
[Firefox](https://ftp.mozilla.org/pub/firefox/releases/108.0.2/linux-x86_64/en-US/firefox-108.0.2.tar.bz2):

            $ wget https://ftp.mozilla.org/pub/firefox/releases/108.0.2/linux-x86_64/en-US/firefox-108.0.2.tar.bz2

   For this demo we use Firefox version (108.0.2).
   Other versions of Firefox may also work (untested).
2. Extract Firefox:

            $ tar xvfj firefox-108.0.2.tar.bz2
            $ cd firefox

3. Compile the instrumentation.
   For this demo we use `counter.c`:

            $ e9compile /usr/share/e9tool/examples/counter.c

4. Instrument the `libxul.so` binary.
   Note that `libxul.so` is the main Firefox binary
   (`firefox-bin` is mostly a wrapper that dynamically loads `libxul`).
   In this example, we will insert `counter` instrumentation for each jump
   instruction:

            $ mv libxul.so libxul.orig.so
            $ e9tool -M jmp -P 'entry()@counter' -c 5 -o libxul.so ./libxul.orig.so 

   Here:

   * "`-M jmp`" matches all jump and conditional jump instructions.
   * "`-P entry()@counter`" inserts a call to the `entry()` function defined
      in `counter.c` for each matching instruction.
   * "`-c 5`" tells E9Patch not to aggressively compress the output binary.
      Since the input binary is quite large (~145MB), the output binary may use
      more mappings beyond the system default.
      This option reduces the number of mappings in exchange for a larger
      output binary.
   * "`-o libxul.so`" specifies that the output binary should be called
      `libxul.so` (replacing the original).
   * "`libxul.orig.so`" is the input binary (renamed from `libxul.so`).

5. Run Firefox with the instrumented `libxul.so`:

            $ ./firefox
            count = 1000000
            count = 2000000
            count = 3000000
            count = 4000000
            ...

Notes:

* The `counter` instrumentation is not thread safe, so the counts will be
  inaccurate for multi-threaded programs like Firefox.
  However, this is just an example for demonstration purposes.
* The instrumented Firefox should be stable and behave the same as the
  original, except for being slower and printing count information.
* Other kinds of instrumentation/rewriting is possible.
  Please see the [E9Tool User
  Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9tool-user-guide.md) for more information.

---
## Instrument Google Chrome?

It is also possible to instrument Google Chrome using E9Tool/E9Patch.
However, for modern versions of Chrome, this can be troublesome:

1. Chrome frequently uses data-in-code; and
2. Chrome seems to copy some code to different locations at runtime.
   This breaks some of the basic assumptions for static binary rewriting.

It is possible to manually exclude affected regions from rewriting (see
E9Tool's `-E` option).
However, this process is manual, and depends on the specific Chrome version.

For older versions of Chrome (circa 2020), it is possible to successfully
rewrite Chrome by excluding all code before the "`ChromeMain`" symbol:

        $ e9tool -E '.text..ChromeMain' ...

Here:

*  "`-E '.text..ChromeMain'`" tells E9Tool to ignore all code in the
"`.text`" section before `ChromeMain`, which is usually <3% of all code.

This simple trick no longer works for modern versions of Chrome.

