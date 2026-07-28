/* Caisse Pro V12.2 — couche locale-first / hors connexion */
(() => {
  const ACTIVATION_KEY = 'caissepro.offline.activation.v2';
  const AUTOLOGIN_KEY = 'caissepro.offline.autologin.v2';
  const LOCAL_DB_NAME = 'caissepro-local-v2';
  const LOCAL_DB_VERSION = 1;
  let localDbPromise = null;
  let operationSyncRunning = false;
  let extraSyncRunning = false;
  let syncAllTimer = null;

  const original = {
    openApp,
    loadAdminData,
    showView,
    invokeAdmin
  };

  function makeUuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return [...bytes].map((byte, index) => `${index === 4 || index === 6 || index === 8 || index === 10 ? '-' : ''}${byte.toString(16).padStart(2, '0')}`).join('');
  }
  function b64(bytes) {
    let s = '';
    bytes.forEach(byte => { s += String.fromCharCode(byte); });
    return btoa(s);
  }
  function fromB64(value) {
    const s = atob(value);
    return Uint8Array.from(s, c => c.charCodeAt(0));
  }
  async function digestText(value) {
    const text = String(value ?? '');
    if (globalThis.crypto?.subtle) {
      const data = new TextEncoder().encode(text);
      const hash = await crypto.subtle.digest('SHA-256', data);
      return b64(new Uint8Array(hash));
    }
    let hash = 2166136261;
    for (let i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return `fallback-${(hash >>> 0).toString(16)}`;
  }
  async function passwordVerifier(password, saltB64) {
    if (globalThis.crypto?.subtle) {
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(String(password)),
        'PBKDF2',
        false,
        ['deriveBits']
      );
      const bits = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: fromB64(saltB64),
        iterations: 120000
      }, keyMaterial, 256);
      return b64(new Uint8Array(bits));
    }
    return digestText(`${saltB64}|${password}`);
  }
  function readActivation() {
    try {
      const value = JSON.parse(localStorage.getItem(ACTIVATION_KEY) || 'null');
      return value && value.profile && value.client && value.lic ? value : null;
    } catch {
      return null;
    }
  }
  async function saveActivation(user, access, code, password, licence) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const activation = {
      version: 2,
      userId: user.id,
      code: normalizeCode(code || access.profile.code_user),
      passwordSalt: b64(salt),
      passwordVerifier: await passwordVerifier(password, b64(salt)),
      licenceHash: await digestText(String(licence || access.lic.cle_licence).trim()),
      profile: access.profile,
      client: access.client,
      lic: access.lic,
      activatedAt: new Date().toISOString(),
      lastValidatedAt: new Date().toISOString()
    };
    localStorage.setItem(ACTIVATION_KEY, JSON.stringify(activation));
    localStorage.setItem(AUTOLOGIN_KEY, '1');
    return activation;
  }
  async function updateActivationAccess(access) {
    const activation = readActivation();
    if (!activation) return;
    activation.profile = access.profile;
    activation.client = access.client;
    activation.lic = access.lic;
    activation.lastValidatedAt = new Date().toISOString();
    localStorage.setItem(ACTIVATION_KEY, JSON.stringify(activation));
  }
  function accessFromActivation(activation) {
    return {
      user: { id: activation.userId },
      access: {
        profile: activation.profile,
        client: activation.client,
        lic: activation.lic
      }
    };
  }
  async function verifyOfflineCredentials(code, password, licence) {
    const activation = readActivation();
    if (!activation) throw new Error('Activation initiale requise avec une connexion Internet.');
    if (normalizeCode(code) !== activation.code) throw new Error('Code utilisateur incorrect.');
    if (expired(activation.lic?.date_fin)) throw new Error('La licence enregistrée sur cet appareil a expiré.');
    const [passwordHash, licenceHash] = await Promise.all([
      passwordVerifier(password, activation.passwordSalt),
      digestText(String(licence || '').trim())
    ]);
    if (passwordHash !== activation.passwordVerifier) throw new Error('Mot de passe incorrect.');
    if (licenceHash !== activation.licenceHash) throw new Error('Clé licence incorrecte.');
    return accessFromActivation(activation);
  }

  function openLocalDb() {
    if (localDbPromise) return localDbPromise;
    localDbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(LOCAL_DB_NAME, LOCAL_DB_VERSION);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains('operations')) {
          const store = database.createObjectStore('operations', { keyPath: '_key' });
          store.createIndex('client_id', 'client_id', { unique: false });
        }
        if (!database.objectStoreNames.contains('extras')) {
          const store = database.createObjectStore('extras', { keyPath: '_key' });
          store.createIndex('client_id', 'client_id', { unique: false });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error('Base locale inaccessible.'));
    });
    return localDbPromise;
  }
  async function idbAll(storeName) {
    const database = await openLocalDb();
    return new Promise((resolve, reject) => {
      const request = database.transaction(storeName, 'readonly').objectStore(storeName).getAll();
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });
  }
  async function idbPut(storeName, value) {
    const database = await openLocalDb();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).put(value);
      tx.oncomplete = () => resolve(value);
      tx.onerror = () => reject(tx.error);
    });
  }
  async function idbDelete(storeName, key) {
    const database = await openLocalDb();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
  function localOperation(row, sync = 'synced') {
    const remoteId = row.id != null && Number(row.id) > 0 ? Number(row.id) : null;
    return {
      ...row,
      id: remoteId ?? Number(row.id || -Date.now()),
      initial: Number(row.initial || 0),
      dep: Number(row.dep || 0),
      bon: Number(row.bon || 0),
      ret: Number(row.ret || 0),
      frais: Number(row.frais || 0),
      final: Number(row.final || 0),
      _key: row._key || (remoteId ? `remote:${row.client_id}:${remoteId}` : `local:${row.client_id}:${makeUuid()}`),
      _sync: row._sync || sync,
      _deleted: Boolean(row._deleted),
      _createdLocal: row._createdLocal || Date.parse(row.created_at || '') || Date.now()
    };
  }
  function operationPayload(row) {
    return {
      client_id: row.client_id,
      created_by: row.created_by,
      tab: row.tab,
      date: row.date,
      initial: Number(row.initial || 0),
      tel: row.tel || '',
      ref: row.ref || '',
      dep: Number(row.dep || 0),
      bon: Number(row.bon || 0),
      ret: Number(row.ret || 0),
      frais: Number(row.frais || 0),
      final: Number(row.final || 0)
    };
  }
  async function localOperationsForClient(includeDeleted = false) {
    if (!currentProfile?.client_id) return [];
    const rows = await idbAll('operations');
    return rows
      .filter(row => String(row.client_id) === String(currentProfile.client_id))
      .filter(row => includeDeleted || !row._deleted)
      .map(row => localOperation(row, row._sync));
  }
  async function reloadOperationsFromLocal() {
    operations = await localOperationsForClient(false);
    renderOperations();
  }
  async function syncPendingOperations() {
    if (operationSyncRunning || !navigator.onLine || !db || !currentProfile?.client_id) return;
    operationSyncRunning = true;
    try {
      const pending = (await localOperationsForClient(true)).filter(row => row._sync && row._sync !== 'synced');
      for (const row of pending) {
        if (row._sync === 'insert') {
          const { data, error } = await db.from('operation').insert(operationPayload(row)).select('*').single();
          if (error) throw error;
          await idbDelete('operations', row._key);
          if (data) await idbPut('operations', localOperation(data, 'synced'));
        } else if (row._sync === 'update') {
          const { error } = await db.from('operation').update(operationPayload(row)).eq('id', row.id).eq('client_id', currentProfile.client_id);
          if (error) throw error;
          await idbPut('operations', { ...row, _sync: 'synced' });
        } else if (row._sync === 'delete') {
          const { error } = await db.from('operation').delete().eq('id', row.id).eq('client_id', currentProfile.client_id);
          if (error) throw error;
          await idbDelete('operations', row._key);
        }
      }
    } finally {
      operationSyncRunning = false;
    }
  }
  async function pullOperations() {
    if (!navigator.onLine || !db || !currentProfile?.client_id) return;
    const { data, error } = await db.from('operation').select('*').eq('client_id', currentProfile.client_id).order('date', { ascending: true }).order('id', { ascending: true });
    if (error) throw error;
    const localRows = await localOperationsForClient(true);
    const pendingById = new Map(localRows.filter(row => Number(row.id) > 0 && row._sync !== 'synced').map(row => [Number(row.id), row]));
    const remoteIds = new Set();
    for (const raw of data || []) {
      const remoteId = Number(raw.id);
      remoteIds.add(remoteId);
      if (pendingById.has(remoteId)) continue;
      await idbPut('operations', localOperation(raw, 'synced'));
    }
    for (const row of localRows) {
      if (row._sync === 'synced' && Number(row.id) > 0 && !remoteIds.has(Number(row.id))) {
        await idbDelete('operations', row._key);
      }
    }
  }

  loadOperations = async function loadOperationsOfflineFirst() {
    if (!currentProfile) return;
    await reloadOperationsFromLocal();
    if (!navigator.onLine || !db) return;
    try {
      await syncPendingOperations();
      await pullOperations();
      await reloadOperationsFromLocal();
    } catch (error) {
      toast(`Mode local actif : ${error.message}`, 'warning', 'Synchronisation différée');
    }
  };
  selectedRows = function selectedRowsOffline() {
    const date = $('dateFilter').value;
    const term = normalizeCode($('operationSearch')?.value);
    return operations
      .filter(row => !row._deleted && row.tab === tab && row.date === date && (!term || normalizeCode(`${row.tel || ''} ${row.ref || ''}`).includes(term)))
      .sort((a, b) => Number(a._createdLocal || a.id || 0) - Number(b._createdLocal || b.id || 0));
  };
  renderOperations = function renderOperationsOffline() {
    if (!$('operationBody')) return;
    const rows = selectedRows();
    $('operationBody').innerHTML = rows.map((row, index) => `<tr><td>${index + 1}</td><td>${formatDate(row.date)}</td><td class="number-cell">${fmt(row.initial)}</td><td>${esc(row.tel || '—')}</td><td class="ref-cell" title="${esc(row.ref || '')}">${esc(row.ref || '—')}</td><td class="number-cell negative">${fmt(row.dep)}</td><td class="number-cell positive">${fmt(row.bon)}</td><td class="number-cell positive">${fmt(row.ret)}</td><td class="number-cell">${fmt(row.frais)}</td><td class="number-cell positive">${fmt(row.final)}</td><td><div class="action-cell"><button class="btn btn-warning btn-xs" onclick="editOperation('${esc(row._key)}')" title="Modifier"><i data-lucide="pencil"></i></button><button class="btn btn-danger btn-xs" onclick="deleteOperation('${esc(row._key)}')" title="Supprimer"><i data-lucide="trash-2"></i></button></div></td></tr>`).join('');
    $('operationEmpty').classList.toggle('hidden', rows.length > 0);
    $('operationBody').closest('table').classList.toggle('hidden', rows.length === 0);
    const dep = rows.reduce((sum, row) => sum + row.dep, 0);
    const ret = rows.reduce((sum, row) => sum + row.ret, 0);
    const bonus = rows.reduce((sum, row) => sum + row.bon, 0);
    const frais = rows.reduce((sum, row) => sum + row.frais, 0);
    $('rowCount').textContent = `${rows.length} ligne${rows.length > 1 ? 's' : ''}`;
    $('tableDepTotal').textContent = fmt(dep);
    $('tableRetTotal').textContent = fmt(ret);
    $('tableBonusTotal').textContent = fmt(bonus);
    $('tableFraisTotal').textContent = fmt(frais);
    $('currentOperatorCount').textContent = rows.length;
    updateTotals();
    refreshIcons();
  };
  getBalanceAtDate = function getBalanceAtDateOffline(operator, date) {
    const rows = operations.filter(row => !row._deleted && row.tab === operator && row.date <= date).sort((a, b) => String(a.date).localeCompare(String(b.date)) || Number(a._createdLocal || a.id || 0) - Number(b._createdLocal || b.id || 0));
    return rows.length ? Number(rows.at(-1).final || 0) : 0;
  };
  findDuplicate = function findDuplicateOffline(row, excludeKey = null) {
    return operations.find(item => item._key !== excludeKey && !item._deleted && item.tab === row.tab && item.date === row.date && row.ref && normalizeCode(item.ref) === normalizeCode(row.ref));
  };
  addOperation = async function addOperationOffline() {
    const row = formData(true);
    const validation = validateOperation(row);
    if (validation) return toast(validation, 'warning');
    const duplicate = findDuplicate(row);
    if (duplicate && !await confirmAction(`La référence « ${row.ref} » existe déjà pour ${OPERATOR_CONFIG[tab].name} à cette date. Enregistrer quand même ?`, 'Référence en double')) return;
    const local = localOperation({ ...row, id: -Date.now(), _sync: 'insert' }, 'insert');
    await idbPut('operations', local);
    await reloadOperationsFromLocal();
    closeForm();
    toast(navigator.onLine ? 'Opération enregistrée localement. Synchronisation en cours.' : 'Opération enregistrée hors connexion sur cet appareil.');
    if (navigator.onLine) scheduleFullSync(150);
  };
  editOperation = function editOperationOffline(key) {
    const row = operations.find(item => item._key === key);
    if (!row) return;
    editId = key;
    $('formCard').classList.add('open');
    $('formTitle').textContent = 'Modifier l’opération';
    $('submitOperationButton').innerHTML = '<i data-lucide="save"></i> Enregistrer les modifications';
    for (const field of ['initial', 'tel', 'ref', 'dep', 'bon', 'ret', 'frais']) $(field).value = row[field] ?? '';
    calc();
    window.scrollTo({ top: 0, behavior: 'smooth' });
    refreshIcons();
  };
  updateOperation = async function updateOperationOffline() {
    if (editId === null) return toast('Sélectionnez une opération à modifier.', 'warning');
    const existing = operations.find(item => item._key === editId);
    if (!existing) return toast('Opération locale introuvable.', 'error');
    const changes = formData();
    const validation = validateOperation(changes);
    if (validation) return toast(validation, 'warning');
    const duplicate = findDuplicate(changes, editId);
    if (duplicate && !await confirmAction(`La référence « ${changes.ref} » existe déjà. Enregistrer quand même ?`, 'Référence en double')) return;
    const sync = existing._sync === 'insert' ? 'insert' : 'update';
    await idbPut('operations', { ...existing, ...changes, _sync: sync, _deleted: false });
    await reloadOperationsFromLocal();
    closeForm();
    toast(navigator.onLine ? 'Modification enregistrée. Synchronisation en cours.' : 'Modification enregistrée hors connexion.');
    if (navigator.onLine) scheduleFullSync(150);
  };
  deleteOperation = async function deleteOperationOffline(key) {
    if (!await confirmAction('Cette opération sera supprimée. Hors connexion, la suppression sera synchronisée plus tard.', 'Supprimer l’opération ?')) return;
    const existing = operations.find(item => item._key === key);
    if (!existing) return;
    if (existing._sync === 'insert' || Number(existing.id) <= 0) {
      await idbDelete('operations', existing._key);
    } else {
      await idbPut('operations', { ...existing, _deleted: true, _sync: 'delete' });
    }
    await reloadOperationsFromLocal();
    toast(navigator.onLine ? 'Suppression enregistrée. Synchronisation en cours.' : 'Suppression enregistrée hors connexion.');
    if (navigator.onLine) scheduleFullSync(150);
  };

  function extraKey(date) {
    return `extra:${currentProfile.client_id}:${date}`;
  }
  async function getLocalExtra(date) {
    const rows = await idbAll('extras');
    return rows.find(row => row._key === extraKey(date)) || null;
  }
  async function syncExtra(date) {
    if (extraSyncRunning || !navigator.onLine || !db || !currentProfile?.client_id) return;
    extraSyncRunning = true;
    try {
      const local = await getLocalExtra(date);
      if (local?._sync === 'pending') {
        const payload = {
          client_id: currentProfile.client_id,
          date,
          tab: 'global',
          especes: Number(local.especes || 0),
          credit: Number(local.credit || 0),
          updated_by: currentUser.id,
          updated_at: new Date().toISOString()
        };
        const { error } = await db.from('caisse_extra').upsert(payload, { onConflict: 'client_id,date,tab' });
        if (error) throw error;
        await idbPut('extras', { ...local, _sync: 'synced', updated_at: payload.updated_at });
      }
    } finally {
      extraSyncRunning = false;
    }
  }
  async function pullExtra(date) {
    if (!navigator.onLine || !db || !currentProfile?.client_id) return;
    const local = await getLocalExtra(date);
    if (local?._sync === 'pending') return;
    const { data, error } = await db.from('caisse_extra').select('tab,especes,credit,updated_at').eq('client_id', currentProfile.client_id).eq('date', date);
    if (error) throw error;
    const rows = data || [];
    const global = rows.find(row => row.tab === 'global');
    const value = global || {
      especes: OPERATOR_KEYS.reduce((sum, key) => sum + Number(rows.find(row => row.tab === key)?.especes || 0), 0),
      credit: OPERATOR_KEYS.reduce((sum, key) => sum + Number(rows.find(row => row.tab === key)?.credit || 0), 0),
      updated_at: new Date().toISOString()
    };
    await idbPut('extras', {
      _key: extraKey(date),
      client_id: currentProfile.client_id,
      date,
      tab: 'global',
      especes: Number(value.especes || 0),
      credit: Number(value.credit || 0),
      updated_at: value.updated_at || new Date().toISOString(),
      _sync: 'synced'
    });
  }
  loadExtras = async function loadExtrasOfflineFirst() {
    if (!currentProfile) return;
    const date = $('dateFilter').value;
    const local = await getLocalExtra(date);
    dayExtras = { global: { especes: Number(local?.especes || 0), credit: Number(local?.credit || 0) } };
    fillCurrentExtraInputs();
    updateTotals();
    if (local?._sync === 'pending') markExtraLocal(); else if (local) markExtraSaved();
    if (!navigator.onLine || !db) return;
    try {
      await syncExtra(date);
      await pullExtra(date);
      const fresh = await getLocalExtra(date);
      dayExtras = { global: { especes: Number(fresh?.especes || 0), credit: Number(fresh?.credit || 0) } };
      fillCurrentExtraInputs();
      updateTotals();
      markExtraSaved();
    } catch (error) {
      markExtraLocal();
      toast(`Trésorerie conservée localement : ${error.message}`, 'warning');
    }
  };
  scheduleSaveExtras = function scheduleSaveExtrasOffline() {
    dayExtras.global = { especes: numberValue('especes'), credit: numberValue('totalCredit') };
    updateTotals();
    markExtraSaving();
    clearTimeout(extrasSaveTimer);
    extrasSaveTimer = setTimeout(saveExtras, 350);
  };
  saveExtras = async function saveExtrasOffline() {
    if (!currentProfile) return;
    const date = $('dateFilter').value;
    const row = {
      _key: extraKey(date),
      client_id: currentProfile.client_id,
      date,
      tab: 'global',
      especes: numberValue('especes'),
      credit: numberValue('totalCredit'),
      updated_at: new Date().toISOString(),
      _sync: 'pending'
    };
    await idbPut('extras', row);
    dayExtras.global = { especes: row.especes, credit: row.credit };
    markExtraLocal();
    updateTotals();
    if (navigator.onLine) scheduleFullSync(150);
  };
  markExtraLocal = function markExtraLocalOffline() {
    const el = $('extraSaveState');
    el.className = 'save-state saving';
    el.lastElementChild.textContent = navigator.onLine ? 'Enregistré localement · synchronisation en attente' : 'Enregistré sur cet appareil · hors connexion';
    $('lastSyncLabel').textContent = 'Local';
  };
  markExtraSaved = function markExtraSavedOffline() {
    const el = $('extraSaveState');
    el.className = 'save-state saved';
    el.lastElementChild.textContent = 'Enregistré localement et synchronisé';
    $('lastSyncLabel').textContent = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  };
  markExtraError = markExtraLocal;

  exportExcel = async function exportExcelOffline() {
    setBusy(true, 'Préparation du fichier...');
    try {
      const allLocalOperations = await localOperationsForClient(false);
      const allExtras = (await idbAll('extras')).filter(row => String(row.client_id) === String(currentProfile.client_id));
      const operationRows = allLocalOperations.map(row => ({
        Opérateur: OPERATOR_CONFIG[row.tab]?.name || row.tab,
        Date: row.date,
        Initial: row.initial,
        Téléphone: row.tel,
        Référence: row.ref,
        Dépôt: row.dep,
        Bonus: row.bon,
        Retrait: row.ret,
        Frais: row.frais,
        Final: row.final
      }));
      if (window.XLSX) {
        const date = $('dateFilter').value;
        const selectedExtra = allExtras.find(row => row.date === date) || {};
        const summary = OPERATOR_KEYS.map(key => {
          const rows = allLocalOperations.filter(row => row.tab === key && row.date === date);
          return {
            Opérateur: OPERATOR_CONFIG[key].name,
            'Solde à la date': getBalanceAtDate(key, date),
            Dépôts: rows.reduce((s, x) => s + x.dep, 0),
            Retraits: rows.reduce((s, x) => s + x.ret, 0),
            Bonus: rows.reduce((s, x) => s + x.bon, 0),
            Frais: rows.reduce((s, x) => s + x.frais, 0),
            'Espèces partagées': Number(selectedExtra.especes || 0),
            'Crédit partagé': Number(selectedExtra.credit || 0),
            Opérations: rows.length
          };
        });
        const extraRows = allExtras.map(row => ({ Date: row.date, Espèces: Number(row.especes || 0), Crédit: Number(row.credit || 0), Synchronisation: row._sync }));
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(operationRows), 'Opérations');
        XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(summary), 'Résumé du jour');
        XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(extraRows), 'Espèces et crédits');
        XLSX.writeFile(wb, `caisse_${currentClient.code_client}_${date}.xlsx`);
      } else {
        const headers = Object.keys(operationRows[0] || { Date: '', Opérateur: '' });
        const csv = [headers.join(';'), ...operationRows.map(row => headers.map(header => `"${String(row[header] ?? '').replaceAll('"', '""')}"`).join(';'))].join('\n');
        const blob = new Blob([`\ufeff${csv}`], { type: 'text/csv;charset=utf-8' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `caisse_${currentClient.code_client}_${$('dateFilter').value}.csv`;
        link.click();
        URL.revokeObjectURL(link.href);
      }
      toast('Fichier généré depuis les données locales.');
    } catch (error) {
      toast(`Export impossible : ${error.message}`, 'error');
    } finally {
      setBusy(false);
    }
  };
  importExcel = async function importExcelOffline(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
      if (!window.XLSX) throw new Error('Le module Excel n’est pas disponible hors connexion. Réouvrez une fois l’application en ligne.');
      setBusy(true, 'Analyse du fichier Excel...');
      const buffer = await file.arrayBuffer();
      const wb = XLSX.read(buffer, { type: 'array' });
      const raw = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { defval: '' });
      let added = 0;
      for (const item of raw) {
        const dep = Number(item.dep ?? item.Dépôt ?? item.Depot ?? 0);
        const bon = Number(item.bon ?? item.Bonus ?? 0);
        const ret = Number(item.ret ?? item.Retrait ?? 0);
        const initial = Number(item.initial ?? item.Initial ?? 0);
        const row = {
          client_id: currentProfile.client_id,
          created_by: currentUser.id,
          tab: normalizeTab(item.tab ?? item.Opérateur ?? item.Operateur),
          date: excelDate(item.date ?? item.Date),
          initial: Number.isFinite(initial) ? initial : 0,
          tel: String(item.tel ?? item.Téléphone ?? item.Telephone ?? ''),
          ref: String(item.ref ?? item.Référence ?? item.Reference ?? ''),
          dep: Number.isFinite(dep) ? dep : 0,
          bon: Number.isFinite(bon) ? bon : 0,
          ret: Number.isFinite(ret) ? ret : 0,
          frais: Number(item.frais ?? item.Frais ?? 0) || 0,
          final: Number(item.final ?? item.Final ?? (initial - dep + bon + ret)) || 0
        };
        if (validateOperation(row)) continue;
        await idbPut('operations', localOperation({ ...row, id: -(Date.now() + added), _sync: 'insert' }, 'insert'));
        added += 1;
      }
      if (!added) throw new Error('Aucune ligne valide à importer.');
      await reloadOperationsFromLocal();
      toast(`${added} opération(s) importée(s) localement.`);
      if (navigator.onLine) scheduleFullSync(150);
    } catch (error) {
      toast(`Import impossible : ${error.message}`, 'error');
    } finally {
      setBusy(false);
      event.target.value = '';
    }
  };

  async function syncAll() {
    if (!navigator.onLine || !db || !currentProfile) return;
    try {
      await syncPendingOperations();
      await syncExtra($('dateFilter').value);
      await pullOperations();
      await pullExtra($('dateFilter').value);
      await reloadOperationsFromLocal();
      const freshExtra = await getLocalExtra($('dateFilter').value);
      dayExtras = { global: { especes: Number(freshExtra?.especes || 0), credit: Number(freshExtra?.credit || 0) } };
      fillCurrentExtraInputs();
      updateTotals();
      markExtraSaved();
    } catch (error) {
      toast(`La synchronisation reprendra automatiquement : ${error.message}`, 'warning');
    }
  }
  function scheduleFullSync(delay = 500) {
    clearTimeout(syncAllTimer);
    syncAllTimer = setTimeout(syncAll, delay);
  }


  openApp = async function openAppOfflineAware(user, access) {
    const result = await original.openApp(user, access);
    updateOnlineStatus();
    return result;
  };

  login = async function loginOfflineAware() {
    const btn = $('loginButton');
    btn.disabled = true;
    setMessage('loginStatus', navigator.onLine ? 'Vérification des accès...' : 'Ouverture hors connexion...', 'info');
    try {
      const code = $('loginCode').value.trim();
      const password = $('loginPassword').value;
      const licence = $('loginLicence').value.trim();
      if (!code || !password || !licence) throw new Error('Veuillez renseigner les trois champs.');
      if (!/^[a-zA-Z0-9._-]{3,50}$/.test(code)) throw new Error('Format du code utilisateur invalide.');
      if (navigator.onLine && db) {
        const { data, error } = await db.auth.signInWithPassword({ email: codeToEmail(code), password });
        if (error || !data.user) throw new Error('Code utilisateur ou mot de passe incorrect.');
        try {
          const access = await fetchAccess(data.user, code, licence);
          await saveActivation(data.user, access, code, password, licence);
          await openApp(data.user, access);
          toast('Activation enregistrée. Cette caisse peut maintenant fonctionner hors connexion.');
        } catch (error) {
          await db.auth.signOut();
          throw error;
        }
      } else {
        const cached = await verifyOfflineCredentials(code, password, licence);
        localStorage.setItem(AUTOLOGIN_KEY, '1');
        await openApp(cached.user, cached.access);
        toast('Caisse ouverte en mode hors connexion.', 'info');
      }
    } catch (error) {
      if (navigator.onLine && readActivation() && /fetch|network|connexion|Failed/i.test(String(error.message))) {
        try {
          const cached = await verifyOfflineCredentials($('loginCode').value, $('loginPassword').value, $('loginLicence').value);
          localStorage.setItem(AUTOLOGIN_KEY, '1');
          await openApp(cached.user, cached.access);
          toast('Serveur inaccessible : mode hors connexion activé.', 'warning');
          return;
        } catch {}
      }
      setMessage('loginStatus', error.message || 'Connexion impossible.', 'error');
    } finally {
      btn.disabled = false;
    }
  };
  restoreSession = async function restoreOfflineAwareSession() {
    const activation = readActivation();
    if (!activation || localStorage.getItem(AUTOLOGIN_KEY) !== '1') return;
    if (expired(activation.lic?.date_fin)) {
      setMessage('loginStatus', 'La licence locale a expiré. Une nouvelle validation en ligne est nécessaire.', 'error');
      return;
    }
    try {
      setBusy(true, navigator.onLine ? 'Restauration de la session...' : 'Ouverture hors connexion...');
      if (navigator.onLine && db) {
        const { data } = await db.auth.getSession();
        if (data.session?.user) {
          try {
            const access = await fetchAccess(data.session.user);
            await updateActivationAccess(access);
            await openApp(data.session.user, access);
            return;
          } catch {}
        }
      }
      const cached = accessFromActivation(activation);
      await openApp(cached.user, cached.access);
    } catch (error) {
      setMessage('loginStatus', error.message || 'Session locale inaccessible.', 'error');
    } finally {
      setBusy(false);
    }
  };
  logout = async function logoutOfflineAware() {
    if (licenceTimer) clearInterval(licenceTimer);
    localStorage.removeItem(AUTOLOGIN_KEY);
    setBusy(true, 'Déconnexion...');
    try { if (db && navigator.onLine) await db.auth.signOut(); } catch {}
    operations = [];
    dayExtras = {};
    currentUser = currentProfile = currentClient = currentLicence = null;
    $('app').style.display = 'none';
    $('loginBox').style.display = 'grid';
    $('loginPassword').value = '';
    $('loginLicence').value = '';
    setMessage('loginStatus', 'Déconnexion effectuée. L’activation hors connexion reste enregistrée sur cet appareil.', 'success');
    setBusy(false);
  };
  startLicenceCheck = function startLicenceCheckOfflineAware() {
    if (licenceTimer) clearInterval(licenceTimer);
    licenceTimer = setInterval(async () => {
      if (expired(currentLicence?.date_fin)) {
        toast('La licence a expiré.', 'error', 'Accès interrompu');
        await logout();
        return;
      }
      if (!navigator.onLine || !db || !currentUser) return;
      try {
        const access = await fetchAccess(currentUser);
        currentProfile = access.profile;
        currentClient = access.client;
        currentLicence = access.lic;
        await updateActivationAccess(access);
        scheduleFullSync(100);
      } catch (error) {
        if (/fetch|network|Failed/i.test(String(error.message))) return;
        toast(error.message, 'error', 'Accès interrompu');
        await logout();
      }
    }, 300000);
  };
  updateOnlineStatus = function updateOnlineStatusOfflineAware() {
    const online = navigator.onLine;
    $('onlineBadge').classList.toggle('offline', !online);
    $('onlineText').textContent = online ? 'En ligne · synchronisation auto' : 'Hors ligne · données locales';
    if ($('adminNav') && currentProfile?.role === 'superadmin') $('adminNav').style.display = online ? 'flex' : 'none';
    if (online && currentProfile) scheduleFullSync(300);
    const status = $('offlineInstallStatus');
    if (status) status.textContent = online ? 'Après cette première activation, l’application fonctionne sans Internet.' : 'Mode hors connexion disponible sur cet appareil.';
  };
  loadAdminData = async function loadAdminDataOnlineOnly() {
    if (!navigator.onLine || !db) return;
    return original.loadAdminData();
  };
  showView = function showViewOnlineAware(name) {
    if (name === 'admin' && (!navigator.onLine || !db)) {
      toast('La gestion des clients, licences et mots de passe nécessite une connexion Internet.', 'warning');
      return;
    }
    return original.showView(name);
  };
  invokeAdmin = async function invokeAdminOnlineOnly(body) {
    if (!navigator.onLine || !db) throw new Error('Connexion Internet requise pour cette action d’administration.');
    return original.invokeAdmin(body);
  };

  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    navigator.serviceWorker.register('./service-worker.js').then(() => navigator.serviceWorker.ready).then(() => {
      const status = $('offlineInstallStatus');
      if (status) status.textContent = 'Mode hors connexion prêt après la première activation.';
    }).catch(() => {
      const status = $('offlineInstallStatus');
      if (status) status.textContent = 'Le mode hors connexion nécessite GitHub Pages ou un serveur HTTPS.';
    });
  }
})();
