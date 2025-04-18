# Запуск

Запуск застосунку здійснюється наступною командою:

<pre> python main.py {user_name} </pre>
де user_name може бути одним із:
<pre> 
    alice
    bob
 </pre>
Приклад:
<pre> python main.py bob </pre>
<pre> python main.py bob </pre>

Для активації режиму відладки використовуйте параметр --debug_mode:

<pre>  python main.py alice --debug_mode </pre>
<pre>   python main.py bob --debug_mode </pre>

# Додадкові відомості

- Алгоритм підтримує тільки ініціалізацію першого повідомлення зі сторони {alice}
- Алгоритм підтримує отримання і розшифрування багато послідовних повідомлень
- Алгоритм підтримує skipped_key логіку розміром до {MAX_SKIP = 20}
