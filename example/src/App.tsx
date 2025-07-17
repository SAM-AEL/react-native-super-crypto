/* eslint-disable react-native/no-inline-styles */
/**
 * Sample React Native App
 * https://github.com/facebook/react-native
 *
 * @format
 */

import React, { useState } from 'react';
import {
  ScrollView,
  StatusBar,
  Text,
  View,
  Button,
  TextInput,
  ActivityIndicator,
  TouchableOpacity,
} from 'react-native';
import SuperCrypto from '../../src/NativeSuperCrypto';

const CARD_STYLE = {
  marginBottom: 24,
  padding: 16,
  borderRadius: 12,
  backgroundColor: '#23272e',
  shadowColor: '#000',
  shadowOpacity: 0.15,
  shadowRadius: 8,
  elevation: 2,
};

function FunctionCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <View style={CARD_STYLE}>
      <Text
        style={{
          fontWeight: 'bold',
          fontSize: 18,
          color: '#fff',
          marginBottom: 8,
        }}
      >
        {title}
      </Text>
      {children}
    </View>
  );
}

// Add mode selector for AES
const MODES = ['GCM', 'CBC'] as const;
type AESMode = (typeof MODES)[number];

export default function App() {
  // State for each function
  const [base64Input, setBase64Input] = useState('hello world');
  const [base64Result, setBase64Result] = useState<{
    encoded?: string;
    decoded?: string;
    error?: string;
  }>({});
  const [hexInput, setHexInput] = useState('hello world');
  const [hexResult, setHexResult] = useState<{
    encoded?: string;
    decoded?: string;
    error?: string;
  }>({});
  const [aesInput, setAesInput] = useState('secret message');
  const [aesKey, setAesKey] = useState('');
  const [aesIv, setAesIv] = useState('');
  const [aesEncrypted, setAesEncrypted] = useState('');
  const [aesResult, setAesResult] = useState<{
    encrypted?: string;
    decrypted?: string;
    error?: string;
  }>({});
  const [hashInput, setHashInput] = useState('hello');
  const [sha256, setSha256] = useState('');
  const [sha512, setSha512] = useState('');
  const [hmacInput, setHmacInput] = useState('hello');
  const [hmacKey, setHmacKey] = useState('key');
  const [hmac256, setHmac256] = useState('');
  const [hmac512, setHmac512] = useState('');
  const [pbkdf2Password, setPbkdf2Password] = useState('password');
  const [pbkdf2Salt, setPbkdf2Salt] = useState('');
  const [pbkdf2Result, setPbkdf2Result] = useState('');
  const [scryptPassword, setScryptPassword] = useState('password');
  const [scryptSalt, setScryptSalt] = useState('');
  const [scryptResult, setScryptResult] = useState('');
  const [randomBytesLen, setRandomBytesLen] = useState('16');
  const [randomBytes, setRandomBytes] = useState('');
  const [loading, setLoading] = useState<string | null>(null);
  const [aesMode, setAesMode] = useState<AESMode>('GCM');

  // Helper to generate random key/iv
  const genKeyIv = async () => {
    setLoading('aes-key-iv');
    try {
      const key = await SuperCrypto.generateRandomBytes(32);
      const iv = await SuperCrypto.generateRandomBytes(
        aesMode === 'GCM' ? 12 : 16
      );
      setAesKey(key);
      setAesIv(iv);
    } catch (e: any) {
      setAesResult({ error: e?.message || JSON.stringify(e) });
    }
    setLoading(null);
  };

  return (
    <View style={{ flex: 1, backgroundColor: '#181a20', paddingTop: 40 }}>
      <StatusBar barStyle="light-content" />
      <Text
        style={{
          color: '#4f8cff',
          fontWeight: 'bold',
          fontSize: 32,
          textAlign: 'center',
          marginBottom: 18,
          letterSpacing: 1,
        }}
      >
        Super Crypto
      </Text>
      <ScrollView style={{ flex: 1, padding: 16 }}>
        {/* Base64 Card */}
        <FunctionCard title="Base64 Encode / Decode">
          <Text style={{ color: '#aaa' }}>Input:</Text>
          <TextInput
            value={base64Input}
            onChangeText={setBase64Input}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter text"
            placeholderTextColor="#666"
          />
          <View style={{ flexDirection: 'row' }}>
            <Button
              title="Encode"
              onPress={async () => {
                setLoading('base64-encode');
                try {
                  const encoded = await SuperCrypto.base64Encode(base64Input);
                  setBase64Result((r) => ({
                    ...r,
                    encoded,
                    error: undefined,
                  }));
                } catch (e: any) {
                  setBase64Result((r) => ({
                    ...r,
                    error: e?.message || JSON.stringify(e),
                  }));
                }
                setLoading(null);
              }}
            />
            <Button
              title="Decode"
              onPress={async () => {
                setLoading('base64-decode');
                try {
                  const decoded = await SuperCrypto.base64Decode(
                    base64Result.encoded || base64Input
                  );
                  setBase64Result((r) => ({
                    ...r,
                    decoded,
                    error: undefined,
                  }));
                } catch (e: any) {
                  setBase64Result((r) => ({
                    ...r,
                    error: e?.message || JSON.stringify(e),
                  }));
                }
                setLoading(null);
              }}
            />
          </View>
          {base64Result.encoded && (
            <Text style={{ marginTop: 8, color: '#eee' }}>
              Encoded: {base64Result.encoded}
            </Text>
          )}
          {base64Result.decoded && (
            <Text style={{ color: '#eee' }}>
              Decoded: {base64Result.decoded}
            </Text>
          )}
          {base64Result.error && (
            <Text style={{ color: '#ff4f4f' }}>
              Error: {base64Result.error}
            </Text>
          )}
        </FunctionCard>

        {/* Hex Card */}
        <FunctionCard title="Hex Encode / Decode">
          <Text style={{ color: '#aaa' }}>Input:</Text>
          <TextInput
            value={hexInput}
            onChangeText={setHexInput}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter text"
            placeholderTextColor="#666"
          />
          <View style={{ flexDirection: 'row' }}>
            <Button
              title="Encode"
              onPress={async () => {
                setLoading('hex-encode');
                try {
                  const encoded = await SuperCrypto.hexEncode(hexInput);
                  setHexResult((r) => ({
                    ...r,
                    encoded,
                    error: undefined,
                  }));
                } catch (e: any) {
                  if (e instanceof Error) {
                    setHexResult((r) => ({
                      ...r,
                      error: e?.message || JSON.stringify(e),
                    }));
                  }
                }
                setLoading(null);
              }}
            />
            <Button
              title="Decode"
              onPress={async () => {
                setLoading('hex-decode');
                try {
                  const decoded = await SuperCrypto.hexDecode(
                    hexResult.encoded || hexInput
                  );
                  setHexResult((r) => ({
                    ...r,
                    decoded,
                    error: undefined,
                  }));
                } catch (e: any) {
                  if (e instanceof Error) {
                    setHexResult((r) => ({
                      ...r,
                      error: e?.message || JSON.stringify(e),
                    }));
                  }
                }
                setLoading(null);
              }}
            />
          </View>
          {hexResult.encoded && (
            <Text style={{ marginTop: 8, color: '#eee' }}>
              Encoded: {hexResult.encoded}
            </Text>
          )}
          {hexResult.decoded && (
            <Text style={{ color: '#eee' }}>Decoded: {hexResult.decoded}</Text>
          )}
          {hexResult.error && (
            <Text style={{ color: '#ff4f4f' }}>Error: {hexResult.error}</Text>
          )}
        </FunctionCard>

        {/* AES Encrypt/Decrypt Card - Redesigned */}
        <View
          style={{
            backgroundColor: '#23272e',
            borderRadius: 16,
            padding: 20,
            marginBottom: 28,
            shadowColor: '#000',
            shadowOpacity: 0.2,
            shadowRadius: 12,
            elevation: 4,
          }}
        >
          <Text
            style={{
              fontWeight: 'bold',
              fontSize: 20,
              color: '#fff',
              marginBottom: 12,
              letterSpacing: 0.5,
            }}
          >
            AES Encrypt / Decrypt
          </Text>
          <Text style={{ color: '#aaa', marginBottom: 4 }}>Mode:</Text>
          <View style={{ flexDirection: 'row', marginBottom: 12 }}>
            {MODES.map((mode) => (
              <TouchableOpacity
                key={mode}
                style={{
                  backgroundColor: aesMode === mode ? '#4f8cff' : '#23272e',
                  borderColor: '#4f8cff',
                  borderWidth: 1,
                  borderRadius: 8,
                  paddingVertical: 6,
                  paddingHorizontal: 18,
                  marginRight: 10,
                }}
                onPress={() => setAesMode(mode)}
              >
                <Text
                  style={{
                    color: aesMode === mode ? '#fff' : '#aaa',
                    fontWeight: 'bold',
                  }}
                >
                  {mode}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
          <Text style={{ color: '#aaa', marginBottom: 4 }}>Input:</Text>
          <TextInput
            value={aesInput}
            onChangeText={setAesInput}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter plaintext"
            placeholderTextColor="#666"
          />
          <Text style={{ color: '#aaa', marginBottom: 4 }}>
            Key (base64, 32 bytes):
          </Text>
          <TextInput
            value={aesKey}
            onChangeText={setAesKey}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Generate or paste key"
            placeholderTextColor="#666"
            autoCapitalize="none"
          />
          <Text style={{ color: '#aaa', marginBottom: 4 }}>
            IV (base64, {aesMode === 'GCM' ? '12' : '16'} bytes):
          </Text>
          <TextInput
            value={aesIv}
            onChangeText={setAesIv}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Generate or paste IV"
            placeholderTextColor="#666"
            autoCapitalize="none"
          />
          <View style={{ flexDirection: 'row', marginBottom: 12 }}>
            <TouchableOpacity
              style={{
                backgroundColor: '#4f8cff',
                borderRadius: 8,
                paddingVertical: 10,
                paddingHorizontal: 16,
                marginRight: 8,
              }}
              onPress={genKeyIv}
              disabled={loading === 'aes-key-iv'}
            >
              <Text style={{ color: '#fff', fontWeight: 'bold' }}>
                Generate Key+IV
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={{
                backgroundColor: '#4f8cff',
                borderRadius: 8,
                paddingVertical: 10,
                paddingHorizontal: 16,
                marginRight: 8,
              }}
              onPress={async () => {
                setLoading('aes-encrypt');
                try {
                  const encrypted = await SuperCrypto.aesEncrypt(
                    aesInput,
                    aesKey,
                    aesIv || null,
                    aesMode
                  );
                  setAesEncrypted(encrypted);
                  setAesResult((r) => ({ ...r, encrypted, error: undefined }));
                } catch (e: any) {
                  setAesResult((r) => ({
                    ...r,
                    error: e?.message || JSON.stringify(e),
                  }));
                }
                setLoading(null);
              }}
              disabled={loading === 'aes-encrypt'}
            >
              <Text style={{ color: '#fff', fontWeight: 'bold' }}>Encrypt</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={{
                backgroundColor: '#4f8cff',
                borderRadius: 8,
                paddingVertical: 10,
                paddingHorizontal: 16,
              }}
              onPress={async () => {
                setLoading('aes-decrypt');
                try {
                  const decrypted = await SuperCrypto.aesDecrypt(
                    aesEncrypted,
                    aesKey,
                    aesIv || null,
                    aesMode
                  );
                  setAesResult((r) => ({ ...r, decrypted, error: undefined }));
                } catch (e: any) {
                  if (e instanceof Error) {
                    setAesResult((r) => ({
                      ...r,
                      error: e?.message || JSON.stringify(e),
                    }));
                  }
                }
                setLoading(null);
              }}
              disabled={loading === 'aes-decrypt'}
            >
              <Text style={{ color: '#fff', fontWeight: 'bold' }}>Decrypt</Text>
            </TouchableOpacity>
          </View>
          {aesResult.encrypted && (
            <Text style={{ color: '#4f8cff', marginBottom: 4 }}>
              Encrypted: {aesResult.encrypted}
            </Text>
          )}
          {aesResult.decrypted && (
            <Text style={{ color: '#4f8cff', marginBottom: 4 }}>
              Decrypted: {aesResult.decrypted}
            </Text>
          )}
          {aesResult.error && (
            <Text style={{ color: '#ff4f4f', marginBottom: 4 }}>
              Error: {aesResult.error}
            </Text>
          )}
        </View>

        {/* SHA256/SHA512 Card */}
        <FunctionCard title="SHA256 / SHA512 Hash">
          <Text style={{ color: '#aaa' }}>Input:</Text>
          <TextInput
            value={hashInput}
            onChangeText={setHashInput}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter text"
            placeholderTextColor="#666"
          />
          <View style={{ flexDirection: 'row' }}>
            <Button
              title="SHA256"
              onPress={async () => {
                setLoading('sha256');
                try {
                  setSha256(await SuperCrypto.sha256(hashInput));
                } catch (e: any) {
                  setSha256(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
            <Button
              title="SHA512"
              onPress={async () => {
                setLoading('sha512');
                try {
                  setSha512(await SuperCrypto.sha512(hashInput));
                } catch (e: any) {
                  setSha512(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
          </View>
          {sha256 ? (
            <Text style={{ color: '#eee' }}>SHA256: {sha256}</Text>
          ) : null}
          {sha512 ? (
            <Text style={{ color: '#eee' }}>SHA512: {sha512}</Text>
          ) : null}
        </FunctionCard>

        {/* HMAC Card */}
        <FunctionCard title="HMAC SHA256 / SHA512">
          <Text style={{ color: '#aaa' }}>Input:</Text>
          <TextInput
            value={hmacInput}
            onChangeText={setHmacInput}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter text"
            placeholderTextColor="#666"
          />
          <Text style={{ color: '#aaa', marginTop: 4 }}>Key:</Text>
          <TextInput
            value={hmacKey}
            onChangeText={setHmacKey}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter key"
            placeholderTextColor="#666"
          />
          <View style={{ flexDirection: 'row' }}>
            <Button
              title="HMAC-SHA256"
              onPress={async () => {
                setLoading('hmac256');
                try {
                  setHmac256(await SuperCrypto.hmacSha256(hmacInput, hmacKey));
                } catch (e: any) {
                  setHmac256(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
            <Button
              title="HMAC-SHA512"
              onPress={async () => {
                setLoading('hmac512');
                try {
                  setHmac512(await SuperCrypto.hmacSha512(hmacInput, hmacKey));
                } catch (e: any) {
                  setHmac512(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
          </View>
          {hmac256 ? (
            <Text style={{ color: '#eee' }}>HMAC-SHA256: {hmac256}</Text>
          ) : null}
          {hmac512 ? (
            <Text style={{ color: '#eee' }}>HMAC-SHA512: {hmac512}</Text>
          ) : null}
        </FunctionCard>

        {/* PBKDF2 Card */}
        <FunctionCard title="PBKDF2">
          <Text style={{ color: '#aaa' }}>Password:</Text>
          <TextInput
            value={pbkdf2Password}
            onChangeText={setPbkdf2Password}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter password"
            placeholderTextColor="#666"
          />
          <Text style={{ color: '#aaa', marginTop: 4 }}>Salt (base64):</Text>
          <TextInput
            value={pbkdf2Salt}
            onChangeText={setPbkdf2Salt}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Generate or paste salt"
            placeholderTextColor="#666"
            autoCapitalize="none"
          />
          <View style={{ flexDirection: 'row', marginBottom: 8 }}>
            <Button
              title="Generate Salt"
              onPress={async () => {
                setLoading('pbkdf2-salt');
                try {
                  setPbkdf2Salt(await SuperCrypto.generateSalt(16));
                } catch (e: any) {
                  setPbkdf2Result(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
            <Button
              title="Derive Key"
              onPress={async () => {
                setLoading('pbkdf2-derive');
                try {
                  setPbkdf2Result(
                    await SuperCrypto.pbkdf2(
                      pbkdf2Password,
                      pbkdf2Salt,
                      10000,
                      32,
                      'SHA256'
                    )
                  );
                } catch (e: any) {
                  setPbkdf2Result(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
          </View>
          {pbkdf2Result ? (
            <Text style={{ color: '#eee' }}>Result: {pbkdf2Result}</Text>
          ) : null}
        </FunctionCard>

        {/* Scrypt Card */}
        <FunctionCard title="Scrypt">
          <Text style={{ color: '#aaa' }}>Password:</Text>
          <TextInput
            value={scryptPassword}
            onChangeText={setScryptPassword}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter password"
            placeholderTextColor="#666"
          />
          <Text style={{ color: '#aaa', marginTop: 4 }}>Salt (base64):</Text>
          <TextInput
            value={scryptSalt}
            onChangeText={setScryptSalt}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Generate or paste salt"
            placeholderTextColor="#666"
            autoCapitalize="none"
          />
          <View style={{ flexDirection: 'row', marginBottom: 8 }}>
            <Button
              title="Generate Salt"
              onPress={async () => {
                setLoading('scrypt-salt');
                try {
                  setScryptSalt(await SuperCrypto.generateSalt(16));
                } catch (e: any) {
                  setScryptResult(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
            <Button
              title="Derive Key"
              onPress={async () => {
                setLoading('scrypt-derive');
                try {
                  setScryptResult(
                    await SuperCrypto.scrypt(
                      scryptPassword,
                      scryptSalt,
                      65536,
                      8,
                      1,
                      32
                    )
                  );
                } catch (e: any) {
                  setScryptResult(e?.message || JSON.stringify(e));
                }
                setLoading(null);
              }}
            />
          </View>
          {scryptResult ? (
            <Text style={{ color: '#eee' }}>Result: {scryptResult}</Text>
          ) : null}
        </FunctionCard>

        {/* Random Bytes Card */}
        <FunctionCard title="Generate Random Bytes">
          <Text style={{ color: '#aaa' }}>Length:</Text>
          <TextInput
            value={randomBytesLen}
            onChangeText={setRandomBytesLen}
            style={{
              backgroundColor: '#23272e',
              color: '#fff',
              borderRadius: 8,
              padding: 10,
              borderWidth: 1,
              borderColor: '#333',
              marginBottom: 10,
            }}
            placeholder="Enter length"
            placeholderTextColor="#666"
            keyboardType="numeric"
          />
          <Button
            title="Generate"
            onPress={async () => {
              setLoading('random-bytes');
              try {
                setRandomBytes(
                  await SuperCrypto.generateRandomBytes(Number(randomBytesLen))
                );
              } catch (e: any) {
                setRandomBytes(e?.message || JSON.stringify(e));
              }
              setLoading(null);
            }}
          />
          {randomBytes ? (
            <Text style={{ color: '#eee', marginTop: 8 }}>
              Result: {randomBytes}
            </Text>
          ) : null}
        </FunctionCard>

        {loading && <ActivityIndicator size="large" style={{ margin: 20 }} />}
      </ScrollView>
    </View>
  );
}
