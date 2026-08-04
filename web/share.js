const state = {
  metadata: null,
};

const accessCard = document.getElementById("access-card");
const completeCard = document.getElementById("complete-card");
const expiredCard = document.getElementById("expired-card");
const accessForm = document.getElementById("access-form");
const statusNode = document.getElementById("status");
const downloadButton = document.getElementById("download-button");

function setStatus(message) {
  statusNode.textContent = message;
}

function showCard(card) {
  accessCard.classList.add("hidden");
  completeCard.classList.add("hidden");
  expiredCard.classList.add("hidden");
  card.classList.remove("hidden");
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (item) => item.toString(16).padStart(2, "0")).join("");
}

async function deriveKey(metadata, email, password, pin) {
  const keyMaterial = new TextEncoder().encode(`${email}\n${password}\n${pin}\n${metadata.shareId}`);
  const importedKey = await crypto.subtle.importKey("raw", keyMaterial, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64ToBytes(metadata.kdf.salt),
      iterations: metadata.kdf.iterations,
      hash: metadata.kdf.hash,
    },
    importedKey,
    { name: metadata.cipher.name, length: 256 },
    false,
    ["decrypt"],
  );
}

async function saveFile(fileName, bytes) {
  if ("showSaveFilePicker" in window) {
    const handle = await window.showSaveFilePicker({
      suggestedName: fileName,
      types: [{ description: "ZIP archive", accept: { "application/zip": [".zip"] } }],
    });
    const writable = await handle.createWritable();
    await writable.write(bytes);
    await writable.close();
    return;
  }

  const blob = new Blob([bytes], { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function decryptArchive(metadata, email, password, pin) {
  const key = await deriveKey(metadata, email, password, pin);
  const decrypted = await crypto.subtle.decrypt(
    {
      name: metadata.cipher.name,
      iv: base64ToBytes(metadata.cipher.nonce),
      additionalData: base64ToBytes(metadata.cipher.associatedData),
    },
    key,
    base64ToBytes(metadata.cipher.ciphertext),
  );
  return new Uint8Array(decrypted);
}

function isExpired(metadata) {
  return Date.now() >= new Date(metadata.expiresAt).getTime();
}

async function loadMetadata() {
  const response = await fetch("./share.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("missing_share");
  }
  return response.json();
}

async function handleSubmit(event) {
  event.preventDefault();
  if (!state.metadata) {
    return;
  }
  if (isExpired(state.metadata)) {
    showCard(expiredCard);
    return;
  }

  const formData = new FormData(accessForm);
  const email = normalizeEmail(String(formData.get("email") || ""));
  const password = String(formData.get("password") || "");
  const pin = String(formData.get("pin") || "").trim();
  if (pin.length !== 6) {
    setStatus("Enter the six-digit PIN.");
    return;
  }

  downloadButton.disabled = true;
  setStatus("Decrypting package...");

  try {
    const hashedEmail = await sha256Hex(email);
    if (hashedEmail !== state.metadata.recipientEmailHash) {
      throw new Error("invalid_credentials");
    }
    if (state.metadata.requiresPassword && password.length === 0) {
      throw new Error("invalid_credentials");
    }
    const archive = await decryptArchive(state.metadata, email, password, pin);
    await saveFile(state.metadata.downloadFileName, archive);
    setStatus("");
    showCard(completeCard);
  } catch {
    setStatus("Credentials were not accepted, or the package is no longer available.");
  } finally {
    downloadButton.disabled = false;
  }
}

async function start() {
  try {
    state.metadata = await loadMetadata();
    if (isExpired(state.metadata)) {
      showCard(expiredCard);
      return;
    }
    showCard(accessCard);
    accessForm.addEventListener("submit", handleSubmit);
  } catch {
    showCard(expiredCard);
  }
}

start();