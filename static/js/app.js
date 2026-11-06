// Глобальное состояние фронтенда
let appState = null;
let currentUnitMode = 'both'; // 'rub' | 'kop' | 'both'
let isAdvancedOpen = false;
let selectedSqlTable = 'links';

function formatMoney(kopecks, mode = currentUnitMode) {
    const num = Number(kopecks || 0);
    const rub = (num / 100).toLocaleString('ru-RU', {
        minimumFractionDigits: num % 100 === 0 ? 0 : 2,
        maximumFractionDigits: 2
    });
    const kop = num.toLocaleString('ru-RU');
    if (mode === 'rub') return `${rub} ₽`;
    if (mode === 'kop') return `${kop} коп.`;
    return `${rub} ₽ (${kop} коп.)`;
}

function setBanner(message, endpoint = 'OK') {
    document.getElementById('banner-text').innerText = message;
    document.getElementById('banner-endpoint').innerText = endpoint;
}

function setUnitMode(mode) {
    currentUnitMode = mode;
    ['rub', 'kop', 'both'].forEach(m => {
        const btn = document.getElementById(`unit-${m}`);
        if (m === mode) {
            btn.className = 'px-2.5 py-1 rounded-md font-semibold transition bg-indigo-600 text-white';
        } else {
            btn.className = 'px-2.5 py-1 rounded-md font-semibold transition text-slate-400 hover:text-white';
        }
    });
    if (appState) renderAll(appState);
}

function toggleAdvancedMode() {
    isAdvancedOpen = !isAdvancedOpen;
    const container = document.getElementById('advanced-inspector-container');
    const badge = document.getElementById('advanced-status-badge');
    if (isAdvancedOpen) {
        container.classList.remove('hidden');
        badge.innerText = 'ВКЛ';
        badge.className = 'px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px]';
    } else {
        container.classList.add('hidden');
        badge.innerText = 'ВЫКЛ';
        badge.className = 'px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]';
    }
}

function selectSqlTable(tableName) {
    selectedSqlTable = tableName;
    ['links', 'accounts', 'holds', 'bm_token_exposure', 'custody_shares'].forEach(t => {
        const btn = document.getElementById(`tab-sql-${t}`);
        if (btn) {
            btn.className = (t === tableName)
                ? 'px-3 py-1 rounded bg-indigo-600 text-white cursor-pointer'
                : 'px-3 py-1 rounded bg-slate-800 text-slate-300 cursor-pointer';
        }
    });
    if (appState) renderSqlInspector(appState);
}

async function fetchState() {
    try {
        const res = await fetch('/api/state');
        appState = await res.json();
        renderAll(appState);
    } catch (err) {
        console.error('Ошибка получения состояния:', err);
    }
}

// =============================================================================
// 3 ГЛАВНЫЕ КНОПКИ ПРЕЗЕНТАЦИОННОГО РЕЖИМА
// =============================================================================
async function runQuickPresentationStep1() {
    try {
        document.getElementById('solo-error-box').classList.add('hidden');
        document.getElementById('revealed-success-box').classList.add('hidden');

        // 1. Если ещё не зарегистрирован — выполняем KYC + генерацию токенов
        if (!appState || !appState.wallet.registered) {
            await runStep1KYC();
        }
        // 2. Если на балансе меньше 1 000 ₽ — пополняем депозит клиента (3 000 ₽) и БК (10 000 ₽)
        await fetchState();
        if (appState.accounts.client.available < 100000) {
            await runStep2Deposits();
        }
        // 3. Делаем ставку 1 000 ₽ под кэф 2.40
        await runStep3Bet();
        setBanner(
            '✅ Шаг 1 выполнен: Игрок зарегистрирован под псевдонимом. В Эскроу заморожено 2 400 ₽ (1 000 ₽ ставка игрока + 1 400 ₽ чистый риск букмекера).',
            'POST /api/client/v1/place-bet'
        );
    } catch (e) {
        alert('Ошибка Шага 1: ' + e.message);
    }
}

async function runQuickPresentationStep2() {
    await settleMatch('HOME_WIN');
    setBanner(
        '🏆 Шаг 2 выполнен: Матч завершён победой! Эскроу автоматически выплатил 2 400 ₽ игроку. Итоговый баланс игрока: 4 400 ₽ (+1 400 ₽ чистой прибыли).',
        'POST /api/regulator/v1/events/ev_final_2026/outcome'
    );
}

async function runQuickPresentationStep3() {
    const res = await fetch('/api/regulator/v1/disclosures/solo-attempt', { method: 'POST' });
    const data = await res.json();
    const errBox = document.getElementById('solo-error-box');
    document.getElementById('solo-error-text').innerText = data.message;
    errBox.classList.remove('hidden');
    setBanner(
        '🔒 Шаг 3 (Проверка защиты): Попытка регулятора раскрыть имя игрока в одиночку заблокирована (HTTP 403). Нажмите фиолетовую кнопку ордера Арбитра!',
        'POST /api/regulator/v1/disclosures/solo-attempt -> 403 FORBIDDEN'
    );
    await fetchState();
}

// =============================================================================
// ДЕТАЛЬНЫЕ ДЕЙСТВИЯ МИКРОСЕРВИСОВ
// =============================================================================
async function runStep1KYC() {
    const fullName = document.getElementById('inp-name')?.value || 'Иванов Иван Иванович';
    const passport = document.getElementById('inp-passport')?.value || '4018 123456';
    const res = await fetch('/api/client/v1/register-full', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ full_name: fullName, passport: passport, age: 23 })
    });
    if (!res.ok) throw new Error('Ошибка регистрации KYC');
    setBanner('✅ KYC пройден: ключ разделён на 3 доли Шамира, выпущены несвязываемые токены P_ALPHA и P_BETA.', 'POST /api/client/v1/register-full');
    await fetchState();
}

async function runStep2Deposits() {
    const res = await fetch('/api/demo/deposit-both', { method: 'POST' });
    const d = await res.json();
    if (!res.ok) {
        alert(d.error || 'Ошибка депозита');
        return;
    }
    setBanner('✅ Депозиты внесены: Клиент +3 000 ₽ (300 000 коп.), Букмекер +10 000 ₽ (1 000 000 коп.) в эскроу.', 'POST /api/demo/deposit-both');
    await fetchState();
}

async function runStep3Bet() {
    const res = await fetch('/api/client/v1/place-bet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selection: 'HOME_WIN', stake: 100000, event_id: 'ev_final_2026' })
    });
    const d = await res.json();
    if (!res.ok) {
        alert(d.error || 'Ошибка размещения ставки');
        return;
    }
    await fetchState();
}

async function settleMatch(outcome) {
    const res = await fetch('/api/regulator/v1/events/ev_final_2026/outcome', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ outcome: outcome })
    });
    await res.json();
    await fetchState();
}

async function approveByArbiterOrder() {
    const reason = document.getElementById('inp-court-order')?.value || 'Судебный ордер №42';
    const res = await fetch('/api/arbiter/v1/disclosures/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason })
    });
    const d = await res.json();
    if (!res.ok) {
        alert(d.error || 'Ошибка одобрения арбитром');
        return;
    }
    document.getElementById('solo-error-box').classList.add('hidden');
    setBanner('⚖️ Порог «2 из 3» собран (Регулятор + Арбитр): личность законно расшифрована и запротоколирована в хэш-цепочке.', 'POST /api/arbiter/v1/disclosures/approve');
    await fetchState();
}

async function voluntaryClientDisclose() {
    const res = await fetch('/api/client/v1/disclosures/voluntary', { method: 'POST' });
    if (res.ok) {
        document.getElementById('solo-error-box').classList.add('hidden');
        setBanner('🙋 Клиент добровольно предоставил свою долю #1: личность подтверждена (Регулятор + Клиент).', 'POST /api/client/v1/disclosures/voluntary');
        await fetchState();
    }
}

async function resetDemo() {
    await fetch('/api/demo/reset', { method: 'POST' });
    document.getElementById('solo-error-box').classList.add('hidden');
    document.getElementById('revealed-success-box').classList.add('hidden');
    setBanner('🔄 Демонстрационная база данных сброшена в исходное состояние.', 'POST /api/demo/reset');
    await fetchState();
}

// =============================================================================
// ОТРИСОВКА ИНТЕРФЕЙСА (RENDER)
// =============================================================================
function renderAll(st) {
    // 1. Шапка и Audit Root
    document.getElementById('header-audit-root').innerText = '0x' + (st.regulator.audit_root || '').slice(0, 20) + '...';

    // 2. Карточка 1: Игрок
    const badge = document.getElementById('pres-client-badge');
    if (st.wallet.registered) {
        badge.innerText = `KYC OK • ${st.wallet.client_id}`;
        badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
    } else {
        badge.innerText = 'Ожидание KYC';
        badge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-slate-800 text-slate-400';
    }

    document.getElementById('pres-client-avail').innerText = formatMoney(st.accounts.client.available);
    document.getElementById('pres-client-held').innerText = formatMoney(st.accounts.client.held);
    document.getElementById('pres-token-alpha').innerText = st.wallet.tokens.bk_alpha || '—';
    document.getElementById('pres-token-beta').innerText = st.wallet.tokens.bk_beta || '—';

    // 3. Карточка 2: Нейтральный Сейф (Эскроу)
    const cliHeld = st.accounts.client.held || 0;
    const bkHeld = st.accounts.bookmaker.held || 0;
    const totalHeld = cliHeld + bkHeld;
    document.getElementById('pres-total-escrow-held').innerText = formatMoney(totalHeld);
    document.getElementById('pres-escrow-cli-h').innerText = formatMoney(cliHeld, 'rub');
    document.getElementById('pres-escrow-bk-h').innerText = formatMoney(bkHeld, 'rub');

    const escBadge = document.getElementById('pres-escrow-status');
    if (totalHeld > 0) {
        escBadge.innerText = '🔒 2 ХОЛДА ЗАМОРОЖЕНЫ';
        escBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse';
        document.getElementById('bar-cli-hold').style.width = '42%';
        document.getElementById('bar-bk-hold').style.width = '58%';
    } else if (st.regulator.last_outcome) {
        escBadge.innerText = `✅ КЛИРИНГ: ${st.regulator.last_outcome}`;
        escBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
        document.getElementById('bar-cli-hold').style.width = '0%';
        document.getElementById('bar-bk-hold').style.width = '0%';
    } else {
        escBadge.innerText = 'Готов к приёму';
        escBadge.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-slate-800 text-slate-400';
        document.getElementById('bar-cli-hold').style.width = '0%';
        document.getElementById('bar-bk-hold').style.width = '0%';
    }

    // 4. Карточка 3: Букмекер
    document.getElementById('pres-bk-avail').innerText = formatMoney(st.accounts.bookmaker.available);
    document.getElementById('pres-bk-held').innerText = formatMoney(st.accounts.bookmaker.held);
    const seenTok = st.bookmaker.exposures.length > 0 ? st.bookmaker.exposures[0].token : (st.wallet.tokens.bk_alpha || 'Нет ставок');
    document.getElementById('pres-bk-seen-token').innerText = seenTok;

    // 5. Плашка успешного раскрытия «2 из 3»
    const revBox = document.getElementById('revealed-success-box');
    if (st.disclosure && st.disclosure.status === 'REVEALED' && st.disclosure.revealed_identity) {
        const p = st.disclosure.revealed_identity;
        document.getElementById('revealed-parties').innerText = st.disclosure.collected.join(' + ');
        document.getElementById('revealed-person-details').innerText =
            `Токен ${st.disclosure.subject} -> ФИО: ${p.full_name} | Паспорт: ${p.passport} | Client ID: ${p.client_id}`;
        revBox.classList.remove('hidden');
    } else {
        revBox.classList.add('hidden');
    }

    // 6. Расширенный режим (Технические панели)
    document.getElementById('adv-secret-s').innerText = st.wallet.client_secret || '—';
    document.getElementById('adv-client-share').innerText = st.wallet.client_share || '—';
    document.getElementById('adv-zk-alpha').innerText = st.wallet.zk_proofs.bk_alpha || '—';
    document.getElementById('adv-receipt-count').innerText = `Квитанций: ${st.wallet.receipts.length}`;
    document.getElementById('adv-arbiter-share').innerText = st.arbiter.stored_share || '—';

    // Таблица экспозиции букмекера
    const expTbody = document.getElementById('adv-exposure-tbody');
    if (st.bookmaker.exposures.length === 0) {
        expTbody.innerHTML = '<tr><td colspan="5" class="py-2 text-slate-500 italic">Ставок пока нет</td></tr>';
    } else {
        expTbody.innerHTML = st.bookmaker.exposures.map(x => `
            <tr class="border-b border-slate-800/60">
                <td class="py-1.5 text-indigo-400 font-bold">${x.token}</td>
                <td class="py-1.5">${x.bets_count}</td>
                <td class="py-1.5">${formatMoney(x.total_staked, 'rub')}</td>
                <td class="py-1.5 text-emerald-400 font-bold">${x.won_count}</td>
                <td class="py-1.5"><span class="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-400 text-[10px]">🔒 НЕИЗВЕСТНО</span></td>
            </tr>
        `).join('');
    }

    // Двойная бухгалтерская книга
    const ledgerDiv = document.getElementById('adv-ledger-list');
    if (st.regulator.ledger.length === 0) {
        ledgerDiv.innerHTML = '<div class="text-slate-500 italic">Проводок пока нет</div>';
    } else {
        ledgerDiv.innerHTML = st.regulator.ledger.map(e => `
            <div class="flex justify-between border-b border-slate-800/60 pb-1">
                <span class="text-slate-500">${e.tx_id}</span>
                <span class="text-slate-300">${e.account_id}</span>
                <span class="${e.direction === 'CREDIT' ? 'text-emerald-400' : 'text-rose-400'} font-bold">
                    ${e.direction === 'CREDIT' ? '+' : '−'}${formatMoney(e.amount)}
                </span>
            </div>
        `).join('');
    }

    // Инспектор SQL таблиц
    renderSqlInspector(st);

    // Журнал аудита SHA-256
    const auditTbody = document.getElementById('audit-log-tbody');
    if (st.regulator.audit_logs.length === 0) {
        auditTbody.innerHTML = '<tr><td colspan="6" class="py-3 text-slate-500 italic">Журнал пуст</td></tr>';
    } else {
        auditTbody.innerHTML = st.regulator.audit_logs.map(l => `
            <tr class="border-b border-slate-800/50">
                <td class="py-1.5 px-2 text-emerald-400 font-bold">#${l.seq}</td>
                <td class="py-1.5 px-2 text-slate-400">${l.ts}</td>
                <td class="py-1.5 px-2"><span class="px-2 py-0.5 rounded bg-slate-800 text-slate-200">${l.actor}</span></td>
                <td class="py-1.5 px-2 text-indigo-400 font-bold">${l.action}</td>
                <td class="py-1.5 px-2 text-slate-500">0x${l.prev_hash.slice(0, 14)}...</td>
                <td class="py-1.5 px-2 text-emerald-400">0x${l.current_hash.slice(0, 18)}...</td>
            </tr>
        `).join('');
    }
}

function renderSqlInspector(st) {
    const dumpMap = {
        links: st.regulator.links,
        accounts: [st.accounts.client, st.accounts.bookmaker, st.accounts.house],
        holds: st.regulator.all_holds,
        bm_token_exposure: st.bookmaker.exposures,
        custody_shares: [
            { party: 'client (локально в кошельке)', share: st.wallet.client_share || null },
            { party: 'regulator (БД регулятора)', share: st.regulator.regulator_share || null },
            { party: 'arbiter (БД арбитра)', share: st.arbiter.stored_share || null }
        ]
    };
    document.getElementById('sql-dump-viewer').innerText = JSON.stringify(dumpMap[selectedSqlTable] || [], null, 2);
}

window.addEventListener('DOMContentLoaded', () => {
    fetchState();
});
