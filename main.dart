import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

const _st = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true));
final _aes = AesGcm.with256bits();
final _kdf =
    Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 600000, bits: 256);
final _auth = LocalAuthentication();
final _rng = Random.secure();

List<int> _rnd(int n) => List.generate(n, (_) => _rng.nextInt(256));
Future<String> _enc(List<int> d, SecretKey k) async =>
    base64.encode((await _aes.encrypt(d, secretKey: k)).concatenation());
Future<List<int>> _dec(String s, SecretKey k) => _aes.decrypt(
    SecretBox.fromConcatenation(base64.decode(s), nonceLength: 12, macLength: 16),
    secretKey: k);
Future<SecretKey> _kek(String pin, List<int> salt) =>
    _kdf.deriveKeyFromPassword(password: pin, nonce: salt);

void main() => runApp(const MaterialApp(home: Vault()));

class Vault extends StatefulWidget {
  const Vault({super.key});
  @override
  State<Vault> createState() => _VaultState();
}

class _VaultState extends State<Vault> with WidgetsBindingObserver {
  final _pin = TextEditingController();
  final _note = TextEditingController();
  SecretKey? _master;
  bool _setup = false, _busy = false, _bio = false;
  String _msg = '';

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _init();
  }

  Future<void> _init() async {
    final w = await _st.read(key: 'wrapped');
    final b = await _st.read(key: 'bio_master');
    setState(() {
      _setup = w == null;
      _bio = b != null;
    });
  }

  // Auto-Sperre, sobald die App in den Hintergrund geht
  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s != AppLifecycleState.resumed && _master != null) {
      setState(() {
        _master = null;
        _note.clear();
        _pin.clear();
      });
    }
  }

  Future<bool> _locked() async {
    final f = int.tryParse(await _st.read(key: 'fails') ?? '0') ?? 0;
    final until = int.tryParse(await _st.read(key: 'until') ?? '0') ?? 0;
    final left = until - DateTime.now().millisecondsSinceEpoch;
    if (f >= 3 && left > 0) {
      setState(() => _msg = 'Gesperrt: noch ${(left / 1000).ceil()} s');
      return true;
    }
    return false;
  }

  Future<void> _fail() async {
    final f = (int.tryParse(await _st.read(key: 'fails') ?? '0') ?? 0) + 1;
    await _st.write(key: 'fails', value: '$f');
    if (f >= 3) {
      final secs = 30 * pow(2, min(f - 3, 10)).toInt();
      await _st.write(
          key: 'until',
          value: '${DateTime.now().millisecondsSinceEpoch + secs * 1000}');
    }
    setState(() => _msg = 'Falscher Code ($f Fehlversuche)');
  }

  Future<void> _open(SecretKey master) async {
    await _st.write(key: 'fails', value: '0');
    final n = await _st.read(key: 'notes');
    final text = n == null ? '' : utf8.decode(await _dec(n, master));
    setState(() {
      _master = master;
      _note.text = text;
      _pin.clear();
      _msg = '';
    });
  }

  Future<void> _submit() async {
    if (_busy) return;
    if (_pin.text.length < 6) {
      setState(() => _msg = 'Mindestens 6 Zeichen');
      return;
    }
    setState(() => _busy = true);
    try {
      if (_setup) {
        final salt = _rnd(16), master = _rnd(32);
        final wrapped = await _enc(master, await _kek(_pin.text, salt));
        await _st.write(key: 'salt', value: base64.encode(salt));
        await _st.write(key: 'wrapped', value: wrapped);
        setState(() => _setup = false);
        await _open(SecretKey(master));
      } else {
        if (await _locked()) return;
        final salt = base64.decode((await _st.read(key: 'salt'))!);
        try {
          final m = await _dec(
              (await _st.read(key: 'wrapped'))!, await _kek(_pin.text, salt));
          await _open(SecretKey(m));
        } on SecretBoxAuthenticationError {
          await _fail();
        }
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _bioUnlock() async {
    if (await _locked()) return;
    final ok = await _auth.authenticate(
        localizedReason: 'Tresor entsperren',
        options: const AuthenticationOptions(
            biometricOnly: true, stickyAuth: true));
    if (!ok) return;
    final b = await _st.read(key: 'bio_master');
    if (b != null) await _open(SecretKey(base64.decode(b)));
  }

  Future<void> _enableBio() async {
    final ok = await _auth.authenticate(
        localizedReason: 'Biometrie aktivieren',
        options: const AuthenticationOptions(biometricOnly: true));
    if (!ok) return;
    await _st.write(
        key: 'bio_master',
        value: base64.encode(await _master!.extractBytes()));
    setState(() {
      _bio = true;
      _msg = 'Biometrie aktiviert';
    });
  }

  Future<void> _save() async {
    await _st.write(
        key: 'notes',
        value: await _enc(utf8.encode(_note.text), _master!));
    setState(() => _msg = 'Verschlüsselt gespeichert');
  }

  @override
  Widget build(BuildContext c) {
    if (_master != null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Tresor'), actions: [
          if (!_bio)
            IconButton(
                icon: const Icon(Icons.fingerprint), onPressed: _enableBio),
          IconButton(
              icon: const Icon(Icons.lock),
              onPressed: () => didChangeAppLifecycleState(AppLifecycleState.paused)),
        ]),
        body: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(children: [
            Expanded(
                child: TextField(
                    controller: _note,
                    maxLines: null,
                    expands: true,
                    decoration:
                        const InputDecoration(border: OutlineInputBorder()))),
            const SizedBox(height: 8),
            FilledButton(onPressed: _save, child: const Text('Speichern')),
            Text(_msg),
          ]),
        ),
      );
    }
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.shield, size: 64, color: Theme.of(c).colorScheme.primary),
            const SizedBox(height: 16),
            TextField(
                controller: _pin,
                obscureText: true,
                enableSuggestions: false,
                autocorrect: false,
                decoration: InputDecoration(
                    labelText: _setup ? 'Neuer Code (min. 6)' : 'Code',
                    border: const OutlineInputBorder())),
            const SizedBox(height: 12),
            FilledButton(
                onPressed: _busy ? null : _submit,
                child: Text(_setup ? 'Tresor erstellen' : 'Entsperren')),
            if (_bio && !_setup)
              TextButton.icon(
                  onPressed: _bioUnlock,
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Fingerabdruck / Gesicht')),
            Text(_msg),
          ]),
        ),
      ),
    );
  }
}
