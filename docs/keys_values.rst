Keys and Values
===============

Keys
----

AgaveDB keys are Python ``str`` objects.

You have much flexibility in key naming them but there are rules:

- Minimum key length is 4 characters. Really short keys aren't necessary. You will probably thank yourself for writing user:1001:bugreports instead of u1001bg when it comes time to debug or maintain our code. The added space and memory requirement is trivial.
- Maximum key length is 512 characters, but such long keys aren't a great idea because they will consume memory and will be slow to retrieve. Consider using a hash (such as SHA1) to represent a larger value.
- Schemas are good. Examples include object-type:id and user:1001. Dots, dashes, and underscores are often used as separators.
- Whitespace is not allowed in keynames. Invalid characters will be removed via a safening process.

Values
------

There are two constraints on values:

- The maximum size for an AgaveDB value is currently 4096 bytes.
- AgaveDB values can only be ``str`` objects. Currently, numeric values are coerced to a string representation. Support for lists, dicts, and tuples will be added in future releases.

