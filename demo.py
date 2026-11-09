"""
Сквозной прогон всех четырёх этапов. Запускать после ./run_all.sh

Печатает, что происходит на каждом шаге и что в этот момент лежит у каждой
стороны. По сути это и есть сценарий будущего интерфейса.
"""

import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.config import BOOKMAKERS, BURMALDA_URL, CLIENT_URL, REGULATOR_URL

C = httpx.Client(timeout=20.0)
BK_ALPHA = BOOKMAKERS["bk_alpha"]
BK_BETA = BOOKMAKERS["bk_beta"]


def head(n, text):
    print(f"\n{'=' * 74}\n  ЭТАП {n}. {text}\n{'=' * 74}")


def step(text):
    print(f"\n-- {text}")


def short(x, n=24):
    s = str(x)
    return s if len(s) <= n else s[:n] + "…"


def reset_all():
    for url in [CLIENT_URL, BURMALDA_URL, REGULATOR_URL, *BOOKMAKERS.values()]:
        C.post(f"{url}/reset")
    print("Все базы очищены.")


# ---------------------------------------------------------------------------

reset_all()

head(1, "РЕГИСТРАЦИЯ")

step("Проверяем, что контроль на входе работает: несовершеннолетний")
r = C.post(f"{CLIENT_URL}/kyc", json={
    "full_name": "Петров Пётр Петрович", "passport": "4612 778899",
    "birth_date": "2010-09-01"}).json()
print(f"   -> {r}")
assert r["unlocked"] is False

step("И клиент из списка самозапрета")
r = C.post(f"{CLIENT_URL}/kyc", json={
    "full_name": "Сидоров Иван Иванович", "passport": "4455 010203",
    "birth_date": "1985-01-30"}).json()
print(f"   -> {r}")
assert r["unlocked"] is False

step("Настоящий клиент приходит в центр Бурмалда")
r = C.post(f"{CLIENT_URL}/kyc", json={
    "full_name": "Иванова Анна Петровна", "passport": "4509 123456",
    "birth_date": "1998-04-12"}).json()
print(f"   -> проверено по реестру, приложение разблокировано: {r}")
assert r["unlocked"] is True

step("Телефон генерирует токены, ключи и шифротексты")
issued = C.post(f"{CLIENT_URL}/tokens/generate",
                json={"bookmakers": ["bk_alpha", "bk_beta"]}).json()["issued"]
for it in issued:
    print(f"   {it['bookmaker_id']}:")
    print(f"      токен        {it['token']}")
    print(f"      ключ AES     {short(it['key_wiped_demo_only'])}  <- СТЁРТ сразу после разделения")
    print(f"      шифротекст   {short(it['pd_blob'])}")
    print(f"      доля А       {short(it['share_a_sent'])}  -> Бурмалда -> регулятор")
    print(f"      доля Б       {short(it['share_b_kept'])}  -> остаётся на телефоне")

token_alpha = next(i["token"] for i in issued if i["bookmaker_id"] == "bk_alpha")
token_beta = next(i["token"] for i in issued if i["bookmaker_id"] == "bk_beta")

print("\n   Токены у двух контор разные и ничем не связаны:")
print(f"      {token_alpha}   и   {token_beta}")

step("Кто что может прочитать прямо сейчас")
print(f"   Бурмалда:  {C.get(f'{BURMALDA_URL}/try-read/{token_alpha}').json()['reason']}")
print(f"   Регулятор: {C.get(f'{REGULATOR_URL}/try-read/{token_alpha}').json()['reason']}")

# ---------------------------------------------------------------------------

head(2, "СТАВКА")

step("Смотрим линию у БК Альфа")
for e in C.get(f"{CLIENT_URL}/events", params={"bookmaker_id": "bk_alpha"}).json():
    print(f"   {e['id']}  {e['title']}  {e['odds']}")

step("Клиент ставит 1000 на хозяев. Вместе с подтверждением уезжает доля Б")
r = C.post(f"{CLIENT_URL}/bet", json={
    "bookmaker_id": "bk_alpha", "event_id": "ev_final",
    "selection": "home", "stake": 1000}).json()
print(f"   -> {r}")

step("Что видит букмекер")
db = C.get(f"{BK_ALPHA}/db").json()
for b in db["bets"]:
    print(f"   ставка: токен {b['token']}  {b['event_id']}  {b['selection']}  "
          f"{b['stake']} x {b['odds']}")
print(f"   персональных данных в базе: {db['personal_data_stored']}")
print(f"   шифротекстов в базе:        {db['ciphertexts_stored']}")
print(f"   {C.get(f'{BK_ALPHA}/try-read/{token_alpha}').json()['reason']}")

# ---------------------------------------------------------------------------

head(3, "РАСЧЁТ — делает букмекер")

step("Событие состоялось, победили хозяева")
print(f"   -> {C.post(f'{BK_ALPHA}/settle', json={'event_id': 'ev_final', 'outcome': 'home'}).json()}")

step("Букмекер отправляет логи и долю Б НАПРЯМУЮ регулятору, минуя Бурмалду")
print(f"   -> {C.post(f'{BK_ALPHA}/report').json()}")

print("\n   Проверяем, что Бурмалда по-прежнему ничего не может:")
print(f"   {C.get(f'{BURMALDA_URL}/try-read/{token_alpha}').json()['reason']}")

# ---------------------------------------------------------------------------

head(4, "АГРЕГАЦИЯ У РЕГУЛЯТОРА")

step("Регулятор соединяет две таблицы по токену и складывает доли")
for res in C.post(f"{REGULATOR_URL}/aggregate").json()["results"]:
    if res.get("revealed"):
        print(f"   {res['token']}  РАСКРЫТ: {res.get('full_name')}  "
              f"({res.get('bookmaker_id')}, ставок: {res.get('bets')})")
    else:
        print(f"   {res['token']}  не раскрыт: {res['reason']}")

print(f"\n   Токен у БК Бета ({token_beta}) не раскрыт — клиент там не играл,")
print("   его доля Б осталась на телефоне и никуда не уезжала.")

# ---------------------------------------------------------------------------

print(f"\n{'=' * 74}\n  КТО ЧТО ЗНАЕТ В ИТОГЕ\n{'=' * 74}")

cl = C.get(f"{CLIENT_URL}/db").json()
bu = C.get(f"{BURMALDA_URL}/db").json()
bk = C.get(f"{BK_ALPHA}/db").json()
rg = C.get(f"{REGULATOR_URL}/db").json()

rows = [
    ("Телефон клиента", "да", "свои", "да"),
    ("Букмекер Альфа", f"нет ({bk['personal_data_stored']})", f"да ({len(bk['bets'])})", "нет"),
    ("Центр Бурмалда", f"нет ({bu['personal_data_stored']})", f"нет ({bu['bet_logs_stored']})", "нет"),
    ("Регулятор", f"да ({len(rg['revealed'])})", f"да ({len(rg['reports'])})", "да"),
]
print(f"\n{'сторона':<20}{'личность':<18}{'ставки':<16}{'связь':<8}")
print("-" * 62)
for name, ident, bets, link in rows:
    print(f"{name:<20}{ident:<18}{bets:<16}{link:<8}")

print("\nУ регулятора после агрегации:")
for r in rg["revealed"]:
    print(f"   {r['token']}  ->  {r['full_name']}, паспорт {r['passport']}, "
          f"{r['birth_date']}; ставок: {len(r['bets'])}")

print("\nУ Бурмалды в базе лежит:")
for a in bu["archive"]:
    print(f"   {a['token']}  шифротекст {short(a['pd_blob'])}  "
          f"доля А: {a['share_a']}  (переслана: {a['forwarded']})")

print("\nГотово.")
