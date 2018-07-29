import axios from 'axios';
import sodium from 'libsodium-wrappers';

const context = 'cryptouser';

const computeURL = (server, command) => {
  let protocol = 'https:';
  if (server.match(/^([^:]+|\[.+\])/)[0] === document.location.hostname) {
    // eslint-disable-next-line prefer-destructuring
    protocol = document.location.protocol;
  }
  return `${protocol}//${server}/.well-known/cryptouser/${command}`;
};

const generateSaltInfo = () =>
  ({
    // TODO include host in salt or include it in "context" variable
    salt: sodium.randombytes_buf(16),
    version: '1',
  });

const computeMasterKey = (password, saltInfo) => {
  if (saltInfo.version !== '1') {
    throw new Error('Unsupported saltInfo version');
  }
  return sodium.crypto_pwhash(
    64,
    password,
    saltInfo.salt,
    sodium.crypto_pwhash_OPSLIMIT_SENSITIVE,
    8 * 1024 * 1024,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
};

const computeAccessKey = masterKey =>
  sodium.crypto_kdf_derive_from_key(32, 1, context, masterKey);

const computeEncryptionKey = masterKey =>
  sodium.crypto_kdf_derive_from_key(32, 2, context, masterKey);

const generateNonce = () =>
  sodium.randombytes_buf(24);

const checkVersion = async (server) => {
  const res = await axios.get(computeURL(server, 'version'));
  if (res.data.version !== 1) {
    throw new Error('Invalid server version');
  }
};

const fetchSaltInfo = async (server, username) => {
  const res = await axios.post(computeURL(server, 'get_public'), {
    id: username,
  });
  return res.data.publicData;
};

const fetchData = async (server, username, masterKey) => {
  await checkVersion(server);

  const accessKey = computeAccessKey(masterKey);
  const res = await axios.post(computeURL(server, 'get_protected'), {
    id: username,
    accessKey: sodium.to_base64(accessKey),
  }, {
    headers: {
      Authorization: sodium.to_base64(accessKey),
    },
  });

  const protectedData = sodium.from_base64(res.data.protectedData);
  const nonce = protectedData.slice(0, 24);
  const ciphertext = protectedData.slice(24);
  const encryptionKey = computeEncryptionKey(masterKey);
  const plaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, encryptionKey);
  return JSON.parse(Buffer.from(plaintext).toString());
};

const encrypt = async (data, encryptionKey) => {
  const plaintext = Buffer.from(JSON.stringify(data));
  const nonce = generateNonce();
  const ciphertext = Buffer.concat([
    Buffer.from(nonce),
    Buffer.from(sodium.crypto_secretbox_easy(plaintext, nonce, encryptionKey)),
  ]);
  return ciphertext;
};

const getData = async () => {
  const user = JSON.parse(localStorage.getItem('user'));
  const { server, username } = user;
  const masterKey = sodium.from_base64(user.masterKey);
  return fetchData(server, username, masterKey);
};

const setData = async (privateData) => {
  const user = JSON.parse(localStorage.getItem('user'));
  const { server, username, publicData } = user;
  const masterKey = sodium.from_base64(user.masterKey);
  const accessKey = computeAccessKey(masterKey);
  const encryptionKey = computeEncryptionKey(masterKey);
  const ciphertext = encrypt(privateData, encryptionKey);

  await axios.post(computeURL(server, 'update_user'), {
    id: username,
    accessKey: sodium.to_base64(accessKey),
    publicData,
    protectedData: sodium.to_base64(ciphertext),
  }, {
    headers: {
      Authorization: sodium.to_base64(accessKey),
    },
  });

  sessionStorage.setItem('privateData', sodium.to_base64(privateData));
};

const logIn = async (server, username, password) => {
  await checkVersion(server);

  const saltInfo = await fetchSaltInfo(server, username);
  const masterKey = computeMasterKey(password, saltInfo);
  const privateData = await fetchData(server, username, masterKey);
  const publicData = {
    salt: sodium.to_base64(saltInfo.salt),
    version: saltInfo.version,
  };

  localStorage.setItem('user', JSON.stringify({
    server,
    username,
    publicData,
    masterKey: sodium.to_base64(masterKey),
  }));
  sessionStorage.setItem('privateData', sodium.to_base64(privateData));
};

const logOut = () => {
  sessionStorage.removeItem('privateData');
  localStorage.removeItem('user');
};

const register = async (server, username, password, privateData) => {
  await checkVersion(server);

  const saltInfo = generateSaltInfo();
  const masterKey = computeMasterKey(password, saltInfo);
  const accessKey = computeAccessKey(masterKey);
  const encryptionKey = computeEncryptionKey(masterKey);
  const ciphertext = await encrypt(privateData, encryptionKey);
  const publicData = {
    salt: sodium.to_base64(saltInfo.salt),
    version: saltInfo.version,
  };

  await axios.post(computeURL(server, 'create_user'), {
    id: username,
    accessKey: sodium.to_base64(accessKey),
    publicData,
    protectedData: sodium.to_base64(ciphertext),
  });

  localStorage.setItem('user', JSON.stringify({
    server,
    username,
    publicData,
    masterKey: sodium.to_base64(masterKey),
  }));
  sessionStorage.setItem('privateData', sodium.to_base64(privateData));
};

const deleteUser = async () => {
  const user = JSON.parse(localStorage.getItem('user'));
  const { server, username } = user;
  const masterKey = sodium.from_base64(user.masterKey);
  const accessKey = computeAccessKey(masterKey);
  await axios.post(computeURL(server, 'delete_user'), {
    id: username,
  }, {
    headers: {
      Authorization: sodium.to_base64(accessKey),
    },
  });
  sessionStorage.removeItem('privateData');
  localStorage.removeItem('user');
};

export default {
  checkVersion,
  logIn,
  logOut,
  register,
  deleteUser,
  setData,
  getData,
};
