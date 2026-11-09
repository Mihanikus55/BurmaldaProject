"""
Адреса сервисов. Всё поднимается локально, порты фиксированные.

Четыре роли:
    client_app  8001   телефон клиента
    burmalda    8002   центр Бурмалда (мы)
    bookmaker   8003   букмекер
    regulator   8004   регулятор

Букмекер поднимается дважды — на 8003 и 8005, одним и тем же файлом с
разным BOOKMAKER_ID. Это не пятый сервис, это второй экземпляр третьего.
Нужен он затем, чтобы было видно главное свойство схемы: у двух контор
лежат РАЗНЫЕ токены одного человека, и связать их они не могут.
"""

import os

CLIENT_URL = os.getenv("CLIENT_URL", "http://127.0.0.1:8001")
BURMALDA_URL = os.getenv("BURMALDA_URL", "http://127.0.0.1:8002")
REGULATOR_URL = os.getenv("REGULATOR_URL", "http://127.0.0.1:8004")

BOOKMAKERS = {
    "bk_alpha": os.getenv("BK_ALPHA_URL", "http://127.0.0.1:8003"),
    "bk_beta": os.getenv("BK_BETA_URL", "http://127.0.0.1:8005"),
}

HTTP_TIMEOUT = 10.0
