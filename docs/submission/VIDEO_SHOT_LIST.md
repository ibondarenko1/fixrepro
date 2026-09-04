# FixRepro video shot list

Target duration: 2:10. Record at 1920 x 1080, 30 frames per second, in a full-screen browser at 100 percent zoom. Disable notifications. Use one clean take or simple cuts. Background music is not required; clear narration matters more. Enable captions after upload.

| Time | Picture and exact action | Narration focus |
|---|---|---|
| 0:00 to 0:12 | Open `http://127.0.0.1:8000` before recording. Keep the pointer away from text. Show the FixRepro name and hero heading. | State that a code change does not prove the patch works. |
| 0:12 to 0:28 | Move the pointer to the `PATCH VERIFIED` panel, then sweep once across the three cards without clicking. | Explain the vulnerable, patched, and positive-control contract. |
| 0:28 to 0:48 | Place the pointer on the vulnerable card. Show `1.0.0` to `9.9.0-test`, `ACCEPTED`, and `FAIL`. | Explain integrity-only acceptance of the untrusted update. |
| 0:48 to 1:08 | Move to the patched card, then scroll just enough to bring **Exact same input replayed** into view. | Explain rejection of the exact same package bytes. |
| 1:08 to 1:23 | Scroll slightly up if needed and point to the positive-control card. Show `1.0.0` to `1.1.0`. | Explain why a trusted success proves the intended feature still works. |
| 1:23 to 1:40 | Scroll to the replay proof. Pause over the envelope hash, request hash, and bundle manifest SHA-256. | Explain matching input hashes and independent bundle checking. |
| 1:40 to 1:57 | Scroll to the top. Select **Run live verification** once. Cut the wait, then show `Live local verification` and the completed `PATCH VERIFIED` result. | Explain that the existing deterministic orchestrator ran the real localhost lab. |
| 1:57 to 2:07 | Scroll to the evidence links. Select **Open report** and pause on the report heading and three result cards. | Explain that the report comes from the finalized evidence. |
| 2:07 to 2:10 | Return to the dashboard tab and frame the FixRepro name. Do not click anything. | Deliver the closing sentence. |

## Keep off screen

- Browser bookmarks and personal email
- Devpost account data
- Windows username or local filesystem paths
- Unrelated terminal history
- Notifications
- Private research material
