Elastos.ELA.SideChain.ID version 0.3.0 is now available from:

  <https://download.elastos.org/elastos-did/elastos-did-v0.3.0/>

This is a new minor version release.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/elastos/Elastos.ELA.SideChain.ID/issues>

How to Upgrade
==============

If you are running version release_v0.2.0 and before, you should shut it down and wait until
 it has completely closed, then just copy over `did` (on Linux).

However, as usual, config, keystore and chaindata files are compatible.

Compatibility
==============

Elastos.ELA.SideChain.ID is supported and extensively tested on operating systems
using the Linux kernel. It is not recommended to use Elastos.ELA.SideChain.ID on
unsupported systems.

Elastos.ELA.SideChain.ID should also work on most other Unix-like systems but is not
as frequently tested on them.

As previously-supported CPU platforms, this release's pre-compiled
distribution provides binaries for the x86_64 platform.

0.3.0 change log
=================

Detailed release notes follow
 
- #197 Add transfer testcase and test DID fee 2.0
- #200 
  - Add RPCServiceLevel to config.json to set RPC service level
  - Add verifiable credential into DID payload
  - Add VeriveriﬁableCredential check
  - Add FTCustomid Bloom filter