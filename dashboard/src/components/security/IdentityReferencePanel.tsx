import { IDENTITY_REFERENCE, IDENTITY_ORDER } from '@/lib/identity-reference';

interface Props {
  onClose: () => void;
}

/** Reference modal: what each scanned identity actually has access to in
 * the target, so a finding's evidence can be judged as a genuine privilege
 * bypass vs. expected access for that role. */
export default function IdentityReferencePanel({ onClose }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-500/40" onClick={onClose} />
      <div className="relative w-full max-w-2xl max-h-[85vh] overflow-y-auto bg-gray-950 border border-gray-800 rounded-lg p-6">
        <div className="flex items-start justify-between mb-4 gap-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-100">Test identities &amp; roles</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              What each scanned identity actually has access to in the target — use this to judge
              whether a finding is a genuine privilege bypass or expected access for that role.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 hover:text-gray-200 text-xl leading-none shrink-0"
            aria-label="Close"
          >
            ×
          </button>
        </div>
        <div className="flex flex-col gap-4">
          {IDENTITY_ORDER.map((key) => {
            const info = IDENTITY_REFERENCE[key];
            if (!info) return null;
            return (
              <div key={key} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-medium text-gray-100">{info.label}</h3>
                  <code className="text-xs text-gray-500">{info.key}</code>
                </div>
                <p className="text-sm text-gray-400 mt-1">{info.description}</p>
                <div className="mt-2 text-xs">
                  <span className="text-gray-500">role(s): </span>
                  <span className="text-gray-300">
                    {info.productRoles.length ? info.productRoles.join(', ') : 'none'}
                  </span>
                </div>
                <div className="mt-1 text-xs">
                  <span className="text-gray-500">API access: </span>
                  <span className="text-gray-300">{info.apiAccess}</span>
                </div>
                {info.notes && (
                  <div className="mt-2 text-xs bg-amber-900/20 border border-amber-200 rounded px-2 py-1.5 text-amber-800">
                    {info.notes}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
