# FixRepro video script

A code change does not prove that a security patch works.

I built FixRepro for one repeatable security regression. This is a controlled synthetic IoT lab for an over-the-air software update.

First, the device starts at version 1.0.0, the vulnerable gateway checks integrity but ignores signer trust, it accepts an untrusted signed update, and the device changes to 9.9.0-test. Unsafe behavior reproduced.

Next, FixRepro resets and replays the exact same bytes against the patched gateway. Digital-signature verification rejects the signer. The device stays at 1.0.0.

Blocking everything would be a bad patch, so FixRepro runs a positive control. A trusted update succeeds, and the device reaches 1.1.0. Legitimate behavior is preserved.

The matching hashes prove that both tests used identical input, FixRepro records responses and device transitions, then creates a tamper-evident evidence bundle, and an independent command checks each file and recomputes the deterministic verdict. No language model decides it.

From the dashboard, I can load the verified demo or start a local run. The browser cannot select another target or package.

The same method could fit authorized robotics, smart devices, industrial IoT, and connected-system release pipelines.

PATCH_VERIFIED applies only to this regression under these test conditions. FixRepro turns a security fix into a repeatable, reviewable result instead of an unsupported claim.
