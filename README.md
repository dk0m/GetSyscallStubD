
# GetSyscallStubD

Fetching Fresh System Call Stubs From NTDLL (Read From Disk) In D.


## Compilation
To compile it (To run the example), Run this:
```
$ dmd GetSyscallStubD.D
```
If you want to use it as D module, Place this in the first line of the file:

```
module SyscallStubFetcher;
```
Now you can easily include it in any of your projects, Dont forget to also remove the main function.

## Acknowledgements

NimGetSyscallStub by [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub/), This project is based on the same idea with a few differences.
