# Search Module

Rizin has two search implementations: the new one and the legacy one.

This document only describes the new implementation.
It is implemented in [librz/search/search.c](https://github.com/rizinorg/rizin/blob/dev/librz/search/search.c) and [rz_search.h](https://github.com/rizinorg/rizin/blob/dev/librz/include/rz_search.h),
starting at the comment `// NEW SEARCH BEGIN`.
Everything above this comment is the legacy search code and is not discussed here
because the it will be replaced step by step to the new design.

## Examples

### Command examples

For examples of how to use the search from the command line, please see
the extended help for the search commands.
You can print it with

```bash
# General search help
[0x00000000]> /?
# Extended help for a specific command. In this case, for the string search.
[0x00000000]> /z??
```

You can also configure the search behavior with the `search` settings.

``` bash
# List all search-related options.
[0x00000000]> el search.
```

For more extensive examples, you can refer to the tests in `tests/cmd/cmd_search_*`.

### API Examples

Of course, the search can also be used from our API.

Please refer to `test/integration/test_str_search.c` for an example of how to
search different strings.
The examples are applicable to other information like hashes as well.

## Module Architecture

The three essential components of the search are the
`search collection`, `search and find options`, and the `search space`.

The general workflow of a search is:

1. Create a collection and configure it with the options.
2. Add one or more jobs to the collection.
3. Start the search on a search space (e.g., a buffer of bytes or a graph).
4. The search space is divided into chunks, each of which is given to a "find worker" in a thread.
5. The worker searches for the different jobs and reports any hits.
6. After the whole search space is covered, it returns the hits to the user.

```
                │                                                             
                │                                                             
                │                                                             
    Create      │   ┌────────────┐      ┌─────────────────────┐                
 1. Collection  │   │ Collection │      │ Search/Find Options │                
    & options   │   └────────────┘      └─────────────────────┘                
                │                                                             
                │                                                             
────────────────┼──────────────────────────────────────────────────────────── 
                │   ┌────────────┐      ┌─────────────────────┐                
                │   │ Collection │      │ Search/Find Options │                
 2. Add jobs    │   ├────┬──┬────┤      └─────────────────────┘                
                │   │Job1│  │Job2│                                             
                │   └────┘  └────┘                                             
────────────────┼──────────────────────────────────────────────────────────── 
                │   ┌────────────┐      ┌─────────────────────┐  ┌────────┐    
 3. Start       │   │ Collection ├──┐   │ Search/Find Options │  │ Buffer │    
    Search      │   ├────┬──┬────┤  │   └─────────┬───────────┘  └───┬────┘    
                │   │Job1│  │Job2│  │             │                  │         
  (here on      │   └────┘  └────┘  └───────┐     └──────┐        ┌──┘         
   a buffer)    │                           │            │        │            
                │                           ▼            ▼        ▼            
                │    rz_search_on_buffer(collection , options, buffer, ...)    
                │                                                             
                │                                                             
────────────────┼─────────────────────────────────────────────────────────────
                │              ┌────────┐                                     
                │              │ Buffer │                                     
 4. Divide      │              └───┬────┘                                     
    and         │        ┌─────────┼────────┐                                 
    dispatch    │        ▼         ▼        ▼                                 
                │     ┌──────┐┌──────┐   ┌──────┐                             
                │     │Chunk0││Chunk1│...│ChunkM│ : M chunks                  
                │     └──┬───┘└───┬──┘│  └──────┘                             
                │        │        │   │                                       
                │        │        │   │                                       
                │      ┌─┘        │   └─────────┐                             
                │      ▼          ▼             ▼                             
                │    worker_0() worker_1() ... worker_n() : n threads         
                │          ▲       ▲              ▲                           
                │          ├───────┴─────────┬────┘                           
                │   ┌──────┴───────┐  ┌──────┴───────┐                 
                │   │ Find options │  │  Job1, Job2  │                 
                │   └──────────────┘  └──────────────┘                 
                │                                                             
────────────────┼──────────────────────────────────────────────────────────── 
                │                                                             
 5. Search      │                                                             
                │                 │foreach job in { Job1, Job2 }:             
                │                 │  hits = perform_search(chunk, job)         
                │   worker()─────►│  report_hits(queue, hits)                 
                │                 │                                           
                │                                                             
────────────────┼──────────────────────────────────────────────────────────── 
                │                                                             
 6. Report      │                                                             
    to user     │                           │ // Wait for workers to finish   
                │                           │                                 
                │  rz_search_on_buffer()───►│ hits = pop_all(queue)           
                │                           │ return hits                     
                │                                                             
```

### Search Collection

The central element in a search is the collection object (`RzSearchCollection`).
It manages the search jobs, which are dispatched into threads.

```
            ┌───────────────┐               
            │               │               
            │ String Search │               
            │ Collection    │               
            │               │               
            └───────┬───────┘               
                    │                       
                    │ Owns                  
                    │                       
                    │                       
┌──────────────┐    │   ┌────────────────────┐
│ UTF8 - hello │◄───┴──►│ UTF16le - [wW]orld │
└──────────────┘        └────────────────────┘
```
_A collection with two search jobs: one to search "Hello" in UTF-8 encoding and one to search the regex pattern `[Ww]orld` in UTF-16 little-endian encoding._

There are different collections, one for each kind of information.
At the time of writing, there are collection types for strings, values, bytes, cryptographic data, hashes, and entropy.
Check out the `RZ_OWN RzSearchCollection *rz_search_collection_<KIND>();` functions in `rz_search.h`
to see what is supported.

### Search and Find Options

To configure a search, there are two kinds of options to edit:
the search options (`RzSearchOpt`) and find options (`RzSearchFindOpt`).

The search options are settings common to all kinds of searches.
That is, they are applicable to string, byte, and hash searches, etc.

These include things like the number of threads a search can use
or the chunk size to dispatch to find workers.

The find options, on the other hand, configure the behavior of each find worker doing the matching.
An example is the address alignment a search hit must have.

The options are generally updated via the setters `rz_search_opt_set_*`.

Note that an `RzSearchFindOpt` object is assigned to an `RzSearchOpt` instance,
and the `RzSearchOpt` instance is unique for each search.
So the options are applied to all search jobs.

### Search Space

A search space is simply the thing the search is performed on.

At the time of writing, the module can only search on a `bytes` search space (`RZ_SEARCH_SPACE_BYTES`).
In practice, this means it can search in buffers or binary files.

Later, we will add others like graphs or the knowledge base.

The search space is not represented as an object. Different objects in Rizin can
be of the same search space type. E.g., `RzBuffer` and `RzIO` are both `RZ_SEARCH_SPACE_BYTES`
because they share the property that they are addressable via an integer offset.

## Search-specific notes

### String search

**Performance considerations**

The string search for all kinds of UTF encodings is faster than a linear search
(in practice, something around <0.5s for a 1 GB file).

But for other encodings, or if the encoding is set to `guess` (e.g., via `e str.encoding=guess`),
the search performance will be slower by one or two orders of magnitude.

The reason is that rare encodings (e.g., EBCDIC, IBM) are not supported by our regex engine.
If such an encoding is selected, each chunk is first
scanned for strings of this encoding. The strings will be converted to UTF-8 for matching,
then all candidates are matched against the searched pattern.

Similarly but slower is the search with "guessed" encoding.
It will first scan the chunk and apply some heuristics to guess the encoding,
then scan it again to extract the strings of the guessed encoding,
convert them to UTF-8, and filter the strings with the provided regex pattern.

This whole procedure consumes vastly more resources.

Also, the guessing heuristics can be unreliable and may miss strings.

In small files, the performance is still good enough.
But for large files (>10 MB), the encoding should always be defined.

In the case of EBCDIC or IBM, an alternative is to use the byte regex search `/xr`
instead.
