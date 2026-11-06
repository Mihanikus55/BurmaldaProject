# run_e2e_demo.py
import threading
import time
import requests
from werkzeug.serving import make_server

from arbiter_service import ArbiterService
from bookmaker_service import BookmakerService
from client_service import ClientService
from regulator_service import RegulatorService
import os


class ServerThread(threading.Thread):
    def __init__(self, app, port: int):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


def run_e2e():
    REG_URL = "http://127.0.0.1:5001"
    BK_URL = "http://127.0.0.1:5002"
    ARB_URL = "http://127.0.0.1:5004"

    # 1. Инициализируем 4 взаимодействующих сервиса (используем in-memory SQLite для чистого теста)
    # Удаляем старые БД перед каждым новым запуском теста, чтобы была чистая среда
    for db_file in ["test_regulator.db", "test_bookmaker.db", "test_arbiter.db", "test_client.db"]:
        if os.path.exists(db_file):
            os.remove(db_file)

    regulator = RegulatorService(
        db_url="sqlite:///test_regulator.db",
        bookmaker_internal_urls={"bk_alpha": BK_URL},
    )
    bookmaker = BookmakerService(
        bookmaker_id="bk_alpha",
        regulator_url=REG_URL,
        db_url="sqlite:///test_bookmaker.db",
    )
    arbiter = ArbiterService(
        regulator_url=REG_URL,
        db_url="sqlite:///test_arbiter.db",
    )
    client = ClientService(
        regulator_url=REG_URL,
        arbiter_url=ARB_URL,
        db_url="sqlite:///test_client.db",
    )

    servers = [
        ServerThread(regulator.app, 5001),
        ServerThread(bookmaker.app, 5002),
        ServerThread(client.app, 5003),
        ServerThread(arbiter.app, 5004),
    ]
    for s in servers:
        s.start()
    time.sleep(0.5)

    print("=== ШАГ 1: Регистрация клиента у Регулятора и распределение долей ключа ===")
    reg_info = client.register(full_name="Иванов Иван Иванович", passport="4018 123456", age=23)
    print("Клиент зарегистрирован:", reg_info)

    print("\n=== ШАГ 2: Проверка несвязываемости токенов у разных букмекеров ===")
    tok_alpha, _ = client.get_or_create_token("bk_alpha")
    tok_beta, _ = client.get_or_create_token("bk_beta")
    print(f"Токен у букмекера Alpha: {tok_alpha}")
    print(f"Токен у букмекера Beta:  {tok_beta} (сговор контор не склеивает профиль)")

    print("\n=== ШАГ 3: Пополнение баланса клиента (3 000 ₽) и ликвидности букмекера (10 000 ₽) ===")
    # Все суммы передаются строго в целых копейках (int64): 1 000 ₽ = 100 000 коп.
    client.deposit(3000_00)
    requests.post(f"{BK_URL}/v1/liquidity/top-up", json={"amount": 10000_00}).raise_for_status()
    print("Баланс клиента до ставки:", client.get_balance())

    print("\n=== ШАГ 4: Создание события и размещение ставки 1 000 ₽ под кэф 2.40 ===")
    requests.post(f"{REG_URL}/v1/events", json={
        "event_id": "ev_final_2026",
        "name": "Финал Кубка: Команда А vs Команда Б",
    }).raise_for_status()

    bet_res = client.place_bet(
        bookmaker_id="bk_alpha",
        bookmaker_url=BK_URL,
        event_id="ev_final_2026",
        selection="HOME_WIN",
        stake_kopecks=1000_00,
    )
    print("Ставка принята, квитанция букмекера:", bet_res["bet_id"])

    # Проверяем холды: у клиента захолдировано 1 000 ₽, у букмекера — риск 1 400 ₽ (2400 - 1000)
    cli_acc = client.get_balance()
    bk_acc = requests.get(f"{REG_URL}/v1/accounts/bookmaker:bk_alpha").json()
    print(f"Счёт клиента во время матча:   available={cli_acc['available'] // 100} ₽, held={cli_acc['held'] // 100} ₽")
    print(f"Счёт букмекера во время матча: available={bk_acc['available'] // 100} ₽, held={bk_acc['held'] // 100} ₽")

    print("\n=== ШАГ 5: Завершение матча (победа HOME_WIN) и автоматический расчёт из эскроу ===")
    settle_res = requests.post(
        f"{REG_URL}/v1/events/ev_final_2026/outcome",
        json={"outcome": "HOME_WIN", "source": "official_oracle"},
    ).json()
    print("Результат расчёта:", settle_res)

    cli_acc_after = client.get_balance()
    bk_acc_after = requests.get(f"{REG_URL}/v1/accounts/bookmaker:bk_alpha").json()
    print(f"Счёт клиента после выигрыша:   available={cli_acc_after['available'] // 100} ₽ (+1 400 ₽ чистыми!)")
    print(f"Счёт букмекера после проигрыша: available={bk_acc_after['available'] // 100} ₽ (-1 400 ₽)")

    print("\n=== ШАГ 6: Пороговое раскрытие личности («2 из 3») ===")
    disc_req = requests.post(f"{REG_URL}/v1/disclosures", json={
        "subject_type": "token",
        "subject": tok_alpha,
        "reason": "Проверка по регламенту AML",
        "requester": "audit_department",
    }).json()
    req_id = disc_req["request_id"]

    # Попытка регулятора раскрыть личность в одиночку (только со своей 1 долей):
    solo_attempt = requests.get(f"{REG_URL}/v1/disclosures/{req_id}/result")
    print(f"Попытка раскрытия одной долей регулятора (HTTP {solo_attempt.status_code}):",
          solo_attempt.json()["message"])

    # Независимый арбитр одобряет запрос и присылает 2-ю долю:
    requests.post(f"{ARB_URL}/v1/disclosures/{req_id}/approve", json={
        "client_id": reg_info["client_id"],
        "reason": "Судебный ордер №42",
    }).raise_for_status()

    revealed = requests.get(f"{REG_URL}/v1/disclosures/{req_id}/result").json()
    print("Личность успешно раскрыта при участии", revealed["participating_parties"], "->",
          revealed["revealed_identity"])

    print("\n=== ШАГ 7: Проверка корня хэш-цепочки журнала аудита ===")
    audit_root = requests.get(f"{REG_URL}/v1/audit/root").json()
    print("Корень хэш-цепочки аудита:", audit_root)

    for s in servers:
        s.shutdown()


if __name__ == "__main__":
    run_e2e()
