const PASSWORD_SALT = new Uint32Array([0xb6db27dd, 0xa7e64336, 0x7ec91eba, 0x503563c3]);
const PASSWORD_DIGESTS = new Set([
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  // empty string (testing only)
  '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',  // 'password' (testing only)
  '9f4da28adb6ebdeeede0d057a11f85a4c74821ba2ed5963e6607765b25a59fa0',
]);

new Promise((resolve, reject) => {
  let password = '';
  let nIterations = 1;

  document.getElementById('password').addEventListener('input', async event => {
    const input = /** @type {HTMLInputElement} */(event.target);
    password = input.value;

    const digest = await computeDigest(password);
    console.log(`Password digest: ${digest}`);
    validate();
  });

  document.getElementById('iterations').addEventListener('input', event => {
    const input = /** @type {HTMLInputElement} */(event.target);
    nIterations = Number(input.value);
    validate();
  });

  const setupDialog = /** @type {HTMLDialogElement} */
    (document.getElementById('setup-dialog'));
  const deriveButton = /** @type {HTMLButtonElement} */
    (document.getElementById('derive-button'))

  deriveButton.addEventListener('click', async event => {
    deriveButton.disabled = true;
    
    event.preventDefault();
    try {
      const key = await deriveKeyFromPassword(password, nIterations);
      resolve(key);
      setupDialog.close();
    } catch (e) {
      reject(e);
    } finally {
      /** @type {HTMLInputElement} */(document.getElementById('password')).value = '';
      /** @type {HTMLInputElement} */(document.getElementById('iterations')).value = '1';
    }
  });

  async function validate() {
    const digest = await computeDigest(password);
    deriveButton.disabled = !PASSWORD_DIGESTS.has(digest) || !(nIterations > 0);
  }

  // @ts-ignore
  setupDialog.showModal();
}).then((/** @type {CryptoKey} */ key) => {
  const log = document.getElementById('log');

  document.getElementById('plaintext').addEventListener('input', async event => {
    const textarea = /** @type {HTMLTextAreaElement} */(event.target);
    const plaintext = textarea.value;
    const output = /** @type {HTMLTextAreaElement} */(document.getElementById('ciphertext'));
    log.textContent = '';
    try {
      const ciphertext = await encrypt(key, plaintext);
      // @ts-ignore
      output.value = toBase64Url(ciphertext);
    } catch (e) {
      log.textContent = `Encryption failed: ${e.message}`;
      console.error('Encryption failed:', e);
    }
  });

  document.getElementById('ciphertext').addEventListener('input', async event => {
    const textarea = /** @type {HTMLTextAreaElement} */(event.target);
    const ciphertext = fromBase64Url(textarea.value);
    const output = /** @type {HTMLTextAreaElement} */(document.getElementById('plaintext'));
    log.textContent = '';
    try {
      const plaintext = await decrypt(key, ciphertext);
      // @ts-ignore
      output.value = plaintext;
    } catch (e) {
      log.textContent = `Decryption failed: ${e.message}`;
      console.error('Decryption failed:', e);
    }
  });
});

/**
 * Derives a key from the given password using PBKDF2.
 * @param {string} password The password to derive the key from.
 * @param {number} nIterations The number of iterations for the key derivation.
 * @returns {Promise<CryptoKey>} A promise that resolves to the derived key.
 */
async function deriveKeyFromPassword(password, nIterations) {
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: PASSWORD_SALT,
      iterations: nIterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Compute digest from string.
 * @param {string} s The string to compute the digest from.
 * @returns {Promise<string>} Hex string of the digest.
 */
const computeDigest = (function() {
  const encoder = new TextEncoder();
  return async function(s) {
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(s));
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  };
})();

/**
 * Encrypt a string with AES-GCM.
 * @param {CryptoKey} key The key to use for encryption.
 * @param {string} plaintext
 * @returns {Promise<string>} Encrypted string as base64.
 */
async function encrypt(key, plaintext) {
  // Generate random initialization vector.
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    new TextEncoder().encode(plaintext)
  );

  // Prepend the IV to the ciphertext.
  return btoa(String.fromCharCode(...iv, ...new Uint8Array(ciphertext)));
};

/**
 * Decrypt a string with AES-GCM.
 * @param {CryptoKey} key The key to use for decryption.
 * @param {string} base64
 * @returns {Promise<string>} Decrypted string.
 */
async function decrypt(key, base64) {
  const ciphertext = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  const plaintext = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ciphertext.slice(0, 12),
    },
    key,
    ciphertext.slice(12)
  );
  return new TextDecoder().decode(plaintext);
}

/**
 * Convert a base64 string to base64url.
 * @param {string} base64 The base64 string to convert.
 * @returns {string} The base64url encoded string.
 */
function toBase64Url(base64) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Convert a base64url string to base64.
 * @param {string} base64url The base64url string to convert.
 * @returns {string} The base64 encoded string.
 */
function fromBase64Url(base64url) {
  return base64url.replace(/-/g, '+').replace(/_/g, '/') +
   '=='.slice(0, (4 - base64url.length % 4) % 4);
}