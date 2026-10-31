export function buildPropertyScope(): HTMLElement {
  const panel=document.createElement('section');panel.className='panel';
  panel.setAttribute('aria-labelledby','property-scope-h');
  panel.innerHTML=`<h2 id="property-scope-h">Which property, under which fault model?</h2>
    <p>A valid tag, context commitment, passive-leakage resilience and active-fault resilience answer different questions. The completed two-key ambiguity experiment above remains evidence about key commitment, not a proof of every property below.</p>
    <div class="table-wrap" tabindex="0" role="region" aria-label="AEAD property and fault evidence"><table class="aead-table"><caption>Keep the security claim attached to its model</caption><thead><tr><th scope="col">Claim and context</th><th scope="col">Model and evidence</th><th scope="col">Limit</th></tr></thead><tbody>
    <tr><th scope="row">Ordinary authenticity</th><td>Classical AEAD game; key and allowed nonce usage fixed. An ordinary tamper rejection is one observed control.</td><td>Neither a random wrong-key rejection nor tamper rejection proves context commitment.</td></tr>
    <tr><th scope="row">Full context commitment</th><td>Context includes key, nonce, associated data and message. CL1268 supplies construction-specific theorem conditions.</td><td>Encrypt-then-MAC needs the stated collision-resistance conditions; independent keys and ordinary MAC unforgeability alone do not earn the claim.</td></tr>
    <tr><th scope="row">Differential-fault resistance</th><td>CL1271's MEM theorem restricts fault type, location, count and timing; its real-hash instantiation also has a conjectural boundary.</td><td>A theorem for that restricted model is not a universal physical-security guarantee.</td></tr>
    <tr><th scope="row">Stuck-at fault attack</th><td>CL1091 uses a stronger stuck-at model than the earlier differential-fault theorem.</td><td>This does not refute the theorem under its original restrictions.</td></tr>
    <tr><th scope="row">Combined fault-then-leak resistance</th><td>Faults alter intermediate state before leakage is observed. Specify fault type, location, count, timing and leakage jointly.</td><td>Separate passive-leakage and active-fault results do not automatically compose. LEAF has explicit leakage and challenge/decryption-fault restrictions.</td></tr>
    </tbody></table></div>
    <h3>A fault location changes the question</h3>
    <p>A complete fault claim must name the fault type, location, count, timing, leakage and allowed decryption queries together. Those exact restrictions belong to each cited theorem; this comparison does not instantiate them or assign any implementation a fault-resistance verdict.</p>
    <p>One Encrypt-then-MAC scenario corrupts only the MAC-side read of a ciphertext while leaving the emitted ciphertext unchanged; the attacker then modifies that emitted ciphertext to match. This particular implementation fault is outside the ordinary classical proof model. Distinguish that scenario from a stuck-at fault, a differential fault, a combined fault-then-leak attack and a fault during decryption. None earns a general “physically secure” badge or a recommendation to deploy a custom mode.</p>
    <p>Sources: <a href="https://doi.org/10.46586/tosc.v2024.i2.348-370" target="_blank" rel="noopener noreferrer">Context-Committing Security of Leveled Leakage-Resilient AEAD</a>, pp. 2–3, 6–9, 14–20;
    <a href="https://doi.org/10.46586/tosc.v2022.i4.291-324" target="_blank" rel="noopener noreferrer">Exploring Integrity of AEADs with Faults</a>, pp. 9–15, 26–34;
    <a href="https://doi.org/10.46586/tosc.v2025.i4.199-230" target="_blank" rel="noopener noreferrer">On Constructing AEs with Leakage and Faults</a>, pp. 2, 14–16, 22–25, 31–32. This is a paper-derived scope comparison, not a physical attack reproduction.</p>`;
  return panel;
}
