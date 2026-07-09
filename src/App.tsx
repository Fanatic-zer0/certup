import { useState } from 'react';
import { Shell, type TabId } from '@/components/Shell';
import { CertDecodeTab }  from '@/tabs/CertDecode';
import { CsrDecodeTab }   from '@/tabs/CsrDecode';
import { CertKeyTab }     from '@/tabs/CertKey';
import { CertCsrTab }     from '@/tabs/CertCsr';
import { CsrKeyTab }      from '@/tabs/CsrKey';
import { ChainVerifyTab } from '@/tabs/ChainVerify';
import { CABundleTab }    from '@/tabs/CABundle';
import { KeystoreTab }    from '@/tabs/Keystore';
import { GenCsrTab }      from '@/tabs/GenCsr';
import { GenCertTab }     from '@/tabs/GenCert';
import { ToPfxTab }       from '@/tabs/ToPfx';

export default function App() {
  const [active, setActive] = useState<TabId>('cert-decode');
  return (
    <Shell active={active} onSelect={setActive}>
      {active === 'cert-decode'  && <CertDecodeTab />}
      {active === 'csr-decode'   && <CsrDecodeTab />}
      {active === 'cert-key'     && <CertKeyTab />}
      {active === 'cert-csr'     && <CertCsrTab />}
      {active === 'csr-key'      && <CsrKeyTab />}
      {active === 'chain'        && <ChainVerifyTab />}
      {active === 'ca-bundle'    && <CABundleTab />}
      {active === 'keystore'     && <KeystoreTab />}
      {active === 'gen-csr'      && <GenCsrTab />}
      {active === 'gen-cert'     && <GenCertTab />}
      {active === 'to-pfx'       && <ToPfxTab />}
    </Shell>
  );
}
