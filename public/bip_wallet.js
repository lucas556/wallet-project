// public/bip_wallet.js
// ESM module for browser. Minimal, synchronous API mirroring Python flow.
// NOTE: This module uses jsDelivr CDN ESM endpoints for the crypto libs.

import { generateMnemonic, mnemonicToSeedSync } from 'https://cdn.jsdelivr.net/npm/@scure/bip39/+esm';
import { HDKey } from 'https://cdn.jsdelivr.net/npm/@scure/bip32/+esm';
import { bech32 } from 'https://cdn.jsdelivr.net/npm/@scure/base/+esm';
import { sha256 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes/sha256/+esm';
import { ripemd160 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes/ripemd160/+esm';
import { keccak_256 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes/sha3/+esm';
import * as secp from 'https://cdn.jsdelivr.net/npm/@noble/secp256k1/+esm';

/* Helpers */
function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join('');
}
function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const out = new Uint8Array(hex.length/2);
  for (let i=0;i<out.length;i++) out[i]=parseInt(hex.substr(i*2,2),16);
  return out;
}

/* BTC bech32 (p2wpkh) from compressed pubkey */
function pubkeyToP2WPKH(pubCompressed) {
  const h = ripemd160(sha256(pubCompressed));
  // bech32 expects words
  const words = bech32.toWords(h);
  return bech32.encode('bc', [0, ...words]);
}

/* ETH address from uncompressed pubkey */
function pubkeyToEthAddress(pubCompressed) {
  // get uncompressed without 0x04 prefix
  const uncompressed = secp.getPublicKey(pubCompressed, false).slice(1);
  const hash = keccak_256(uncompressed);
  const addr = bytesToHex(hash.slice(-20));
  // checksum (EIP-55)
  const hashHex = bytesToHex(keccak_256(new TextEncoder().encode(addr)));
  let res = '0x';
  for (let i=0;i<addr.length;i++) {
    const c = addr[i];
    if (/[0-9]/.test(c)) res += c;
    else {
      const v = parseInt(hashHex[i], 16);
      res += (v >= 8) ? c.toUpperCase() : c.toLowerCase();
    }
  }
  return res;
}

/* Public API */
export function generateNewMnemonic(strength = 256) {
  // strength: 128/160/192/224/256
  return generateMnemonic(strength);
}

export function deriveFromMnemonic(mnemonic, passphrase='') {
  if (!mnemonic) throw new Error('mnemonic required');
  const seed = mnemonicToSeedSync(mnemonic, passphrase); // returns Uint8Array
  const root = HDKey.fromMasterSeed(seed);

  // derive BTC (BIP84) m/84'/0'/0'/0/0
  const btcNode = root.derive("m/84'/0'/0'/0/0");
  if (!btcNode.privateKey) throw new Error('BTC private key missing');
  const btcPrivHex = bytesToHex(btcNode.privateKey);
  const btcPub = secp.getPublicKey(btcNode.privateKey, true);
  const btcAddr = pubkeyToP2WPKH(btcPub);

  // derive ETH (BIP44) m/44'/60'/0'/0/0
  const ethNode = root.derive("m/44'/60'/0'/0/0");
  if (!ethNode.privateKey) throw new Error('ETH private key missing');
  const ethPrivHex = bytesToHex(ethNode.privateKey);
  const ethPub = secp.getPublicKey(ethNode.privateKey, true);
  const ethAddr = pubkeyToEthAddress(ethPub);

  return {
    mnemonic,
    seed: bytesToHex(seed),
    btc: { privateKey: btcPrivHex, address: btcAddr },
    eth: { privateKey: ethPrivHex, address: ethAddr }
  };
}
