import { useState } from 'react';
import { decryptScans, type EncBlob, type Scan } from '@/lib/deluluscan-data';

/**
 * Decryption gate for a password-protected report.
 *
 * The findings genuinely are not in the file until the passphrase is entered — a
 * wrong one fails the AES-GCM auth tag, which is what distinguishes "wrong
 * password" from "corrupt payload". The published report is a public URL, so this
 * passphrase is the entire access boundary.
 */
export default function PasswordGate({ blob, onUnlock }: {
  blob: EncBlob;
  onUnlock: (scans: Scan[]) => void;
}) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(e?: React.FormEvent) {
    e?.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError('');
    try {
      onUnlock(await decryptScans(blob, password));
    } catch (err) {
      // Only an AES-GCM tag mismatch means "wrong password". Reporting every
      // failure that way hides real faults (a missing Web Crypto API, a truncated
      // payload) behind a message that sends the viewer off to re-check their
      // passphrase forever.
      const name = (err as { name?: string })?.name ?? '';
      const msg = err instanceof Error ? err.message : String(err);
      const badKey = name === 'OperationError' || /operation-specific reason/i.test(msg);
      setError(
        badKey
          ? 'Wrong password — try again.'
          : `Could not decrypt this report: ${msg || name || 'unknown error'}`
      );
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950 p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-xl border border-slate-800 bg-slate-900 p-7 shadow-2xl"
      >
        <h1 className="text-base font-bold text-slate-100">Deluluscan — Protected Report</h1>
        <p className="mt-1.5 mb-4 text-[12.5px] leading-relaxed text-slate-400">
          This security assessment is encrypted. Enter the passphrase to decrypt and
          view it.
        </p>
        <input
          type="password"
          autoFocus
          aria-label="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Passphrase"
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm
                     text-slate-100 outline-none placeholder:text-slate-600 focus:border-indigo-500"
        />
        {error && (
          <p role="alert" className="mt-2 text-xs text-rose-700">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy || !password}
          className="mt-4 w-full rounded-lg bg-indigo-600 px-3 py-2.5 text-sm font-semibold
                     text-white transition hover:bg-indigo-500 disabled:opacity-50"
        >
          {busy ? 'Decrypting…' : 'Unlock'}
        </button>
      </form>
    </div>
  );
}
