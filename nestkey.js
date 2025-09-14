document.getElementById('nestkey-form').addEventListener('submit', async function(e) {
    e.preventDefault();

    // Gather plain form values
    const category = document.getElementById('category').value;
    const subcategory = document.getElementById('subcategory').value;
    const service = document.getElementById('service').value;
    const accessname = document.getElementById('accessname').value;
    const password = document.getElementById('password').value;
    const add1 = document.getElementById('add1').value;
    const add2 = document.getElementById('add2').value;
    const encKey = document.getElementById('encKey').value; // passphrase, never sent

    async function getKeyMaterial(password) {
        let enc = new TextEncoder();
        return await window.crypto.subtle.importKey(
            "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
        );
    }

    async function deriveAesKey(keyMaterial, salt) {
        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptField(text, keyMaterial) {
        if (!text) return null;
        let salt = window.crypto.getRandomValues(new Uint8Array(16));
        let iv = window.crypto.getRandomValues(new Uint8Array(12));
        let key = await deriveAesKey(keyMaterial, salt);
        let encoded = new TextEncoder().encode(text);
        let ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, key, encoded
        );
        // Return all parts base64-encoded
        return {
            salt: btoa(String.fromCharCode(...salt)),
            iv: btoa(String.fromCharCode(...iv)),
            ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
        };
    }

    try {
        let keyMaterial = await getKeyMaterial(encKey);

        // Encrypt sensitive fields
        let encryptedAccessName = await encryptField(accessname, keyMaterial);
        let encryptedPassword = await encryptField(password, keyMaterial);
        let encryptedAdd1 = await encryptField(add1, keyMaterial);
        let encryptedAdd2 = await encryptField(add2, keyMaterial);

        // Prepare single JSON object
        let payload = {
            category, 
            subcategory, 
            service,
            accessname: encryptedAccessName,
            password: encryptedPassword,
            additional1: encryptedAdd1,
            additional2: encryptedAdd2,
            timestamp: new Date().toISOString()
        };

        // POST to API endpoint
        let response = await fetch('https://your-api-url-here.com/api/insert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            document.getElementById('message').textContent = "Entry saved securely!";
            document.getElementById('nestkey-form').reset();
        } else {
            document.getElementById('message').textContent = "Error while saving.";
        }
    } catch (err) {
        console.error(err);
        document.getElementById('message').textContent = "Encryption or network error!";
    }
});
