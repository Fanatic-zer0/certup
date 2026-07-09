import { Input, Label } from '@/components/ui/input';
import { type KeyAlgoState, EC_CURVE_OPTIONS } from '@/lib/cert-crypto';
import type { KeyAlgo } from '@/lib/cert-crypto';

export function KeyAlgoSelector({
  value,
  onChange,
  native,
}: {
  value: KeyAlgoState;
  onChange: (k: KeyAlgoState) => void;
  native: boolean;
}) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <div>
        <Label>Key Algorithm</Label>
        <select
          className="flex h-8 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          value={value.algo}
          onChange={(e) => onChange({ ...value, algo: e.target.value as KeyAlgo })}
        >
          <option value="rsa">RSA</option>
          {native && <option value="ec">EC (ECDSA)</option>}
          {native && <option value="ed25519">Ed25519</option>}
          {native && <option value="ed448">Ed448</option>}
        </select>
        {!native && (
          <p className="text-[10.5px] mt-1 text-muted-foreground">
            EC / EdDSA generation requires the desktop app.
          </p>
        )}
      </div>
      {value.algo === 'rsa' && (
        <div>
          <Label>Key Size</Label>
          <select
            className="flex h-8 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            value={value.rsaBits}
            onChange={(e) => onChange({ ...value, rsaBits: e.target.value as KeyAlgoState['rsaBits'] })}
          >
            <option value="2048">2048 bits</option>
            <option value="3072">3072 bits</option>
            <option value="4096">4096 bits</option>
          </select>
        </div>
      )}
      {value.algo === 'ec' && (
        <div>
          <Label>Curve</Label>
          <select
            className="flex h-8 w-full rounded-md border border-input bg-background px-3 py-1.5 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            value={value.curve}
            onChange={(e) => onChange({ ...value, curve: e.target.value })}
          >
            {EC_CURVE_OPTIONS.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>
      )}
    </div>
  );
}
