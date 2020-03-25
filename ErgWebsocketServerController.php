<?php /** @noinspection PhpUnused PhpUnhandled */

/**
 * Автор класса Александр Хакимов https://github.com/hackimov
 * Класс реализует обработку вебсоккетов, и дальнейшую работу с клиентов путем отправки сообщений от клиентов к серверу и наоборот
 * Так же класс реализует прослушку и получение информации от эвентов связанных с документами так же путем соединения через отдельный соккет по порту 8001
 * Данный процесс должен работать в фоне!
 */

namespace App\Http\Controllers\API\wss;

use App\Http\Controllers\API\v1\OauthToSessionController;
use App\Http\Controllers\Controller;


class ErgWebsocketServerController extends Controller {

    public static function websocket_start() : void
    {
        $address = 'tcp://127.0.0.1:7746';
        $addr    = parse_url($address);
        if (!isset($addr['scheme'], $addr['host'], $addr['port']) || $addr === false) {
            die('Invalid websocket server address');
        }
        // делаем безлимитным время выполнения скрипта, чтобы он не падал по таймауту
        ini_set('max_execution_time', 0);

        // создаём вебсоккет которым будет пользоваться frontend
        $client_socket  = stream_socket_server((in_array($addr['scheme'], ['wss', 'tls']) ? 'tls' : 'tcp').'://'.$addr['host'].':'.$addr['port'], $client_socket_start_error_number,  $client_socket_start_error_string);

        /************************** Убиваем скрипт если мы не можем создать соккет **********************/
        if (!$client_socket) {
            // убиваем скрипт если мы не можем обрабатывать входщие вебсоккеты
            die("$client_socket_start_error_string ($client_socket_start_error_number)\n");
        }
        /** *********************************************************************************************/

        $clients_ident_data = [];
        // сюда мы будем записывать все входящие коннекты
        $client_connects  = [];
        while (true) {

            // формируем массив прослушиваемых сокетов:
            $client_read    = $client_connects;
            $client_read[]  = $client_socket;
            $client_write   = $client_except = null;

            if(!stream_select($client_read,   $client_write,  $client_except, null)){
                continue;
            }

            // есть новое соединение с фронта
            if (in_array($client_socket, $client_read, true)) {

                $client_connect = stream_socket_accept($client_socket, -1);

                if(!empty($client_connect)){
                    $client_info = self::handshake($client_connect);
                }

                if(!empty($client_info)){
                    // мы поздаровались с клиентом, теперь начинаем его идентификацию

                    // получаем его access token из коннекта
                    $token = self::check_access_token($client_info);

                    // если токен не бэкэнда или по токену нет сессии отключаем соединение так как это кто то левый
                    if($token !== 'QkFDS19BQ0NFU1NfVE9LRU4=' && OauthToSessionController::get_session_data($token) === false){
                        fclose($client_connect);
                        continue;
                    }

                    if(OauthToSessionController::get_session_data($token) !== false){
                        /** @noinspection PhpUndefinedMethodInspection */
                        $session_data = OauthToSessionController::get_session_data($token);
                    }

                    // если это наше бэкэнд соединение у него нет сессии
                    if($token === 'QkFDS19BQ0NFU1NfVE9LRU4='){
                        $session_data = [
                            'user_id'       => null,
                            'mailbox_id'    => null,
                            'account_id'    => null,
                            'structure_id'  => null,
                            'contragent_id' => null
                        ];
                    }

                    // добавляем данные к переменную идентификации
                    // работа с этим масиивом должна быть синхронна с работой массива коннектов (он ниже)
                    // т.е. если какой то клиент отключился из этого массива мы тоже всю инфу о сессии грохнем
                    $clients_ident_data[] = $session_data;
                    // добавляем его в список необходимых для обработки
                    $client_connects[] = $client_connect;
                    // вызываем пользовательский сценарий
                    self::client_on_open($client_connect);
                    unset($session_data);
                }
                unset($client_read[array_search($client_socket, $client_read, true)]);


            }

            // обрабатываем все соединения фронтенда и наших бэкенд эвентов
            foreach ($client_read as $client_connect) {

                $client_data = fread($client_connect, 100000);
                // если от нас отключился клиент, забываем его.
                if (!$client_data) {
                    // закрываем соединение
                    fclose($client_connect);
                    // удаляем ресурс соединения из массива соединенных клиентов и очищаем данные о клиенте которые мы получили из сессии
                    unset($clients_ident_data[array_search($client_connect, $client_connects, true)], $client_connects[array_search($client_connect, $client_connects, true)]);
                    // выходим из форича чтобы в дальнейшем не делать обработку по этому конкретному клиенту
                    break;
                }

                if(self::is_json($client_data)){
                    $server_event_array = json_decode($client_data, true);

                    // обрабатываем поле эвента если оно есть
                    if(isset($server_event_array['event'])){
                        $event = $server_event_array['event'];

                        // у нас есть 4 типа зарегистрированных эвентов исходящих от бэкэнда и в зависимости от типа отсылаем той группе пользователей кому принадлежит запрос
                        switch ($event){
                            // отсылаем пакет всем подключенным клиентам
                            case 'all_event':
                                self::send_to_all_event($client_connects, $client_data);
                                break;

                            // отсылаем пакет всем клиентам с этим майлбоксом
                            case 'mailbox_event':
                                self::send_to_mailbox_event($client_connects, $clients_ident_data, $client_data);
                                break;

                            // отсылаем пакет всем клиентам с этой структурой
                            case 'structure_event':
                                self::send_to_structure_event($client_connects, $clients_ident_data, $client_data);
                                break;

                            // отсылаем пакет указанному пользователю
                            case 'user_event':
                                self::send_to_user_event($client_connects, $clients_ident_data, $client_data);
                                break;
                        }
                    }
                }

                // а тут мы работаем с клиентом который который послал запрос с фронтенда
                self::client_to_server($client_connect, $client_connects, $clients_ident_data,  $client_data);
            }


        }
        fclose($client_socket);
    }

    // функция вызывается когда клиент только подключился
    public static function client_on_open($client_connect): void
    {
        fwrite($client_connect, self::encode('{"message":"successfully connected"}'));
    }

    // функция вызывается когда клиент отключился
    public static function client_on_close($client_connect): void
    {
        // в дальнейшем тут можно будет писать события
    }

    // событие которое инициализировал клиент с фронтенда
    public static function client_to_server($client_connect, $client_connects, $clients_ident_data, $data): void
    {
        $message =  self::decode($data)['payload'] . "\n";

        if(trim($message) === 'getMe'){
            $session_array = $clients_ident_data[array_search($client_connect, $client_connects, true)];
            $session_json = json_encode($session_array);
            fwrite($client_connect, self::encode($session_json));
        }

        if(trim($message) === 'Ты кто такой?'){
            fwrite($client_connect, self::encode('Я EREGISTER!!!'));
        }

        if(trim($message) === 'Когда мы запустимся?'){
            fwrite($client_connect, self::encode('Очень скоро!'));
        }
    }


    // функция которая рассылает пакет всем сидящим онлайн мэйлбоксам
    public static function send_to_all_event($client_connects, $message) : void
    {
        // рассылаем событие всем маилбоксам кто онлайн
        foreach ($client_connects as $client_connect){
            fwrite($client_connect, self::encode($message));
        }
    }

    // функция которая рассылает пакет всем сидящим онлайн мэйлбоксам
    public static function send_to_mailbox_event($client_connects, $clients_ident_data, $message) : void
    {
        $message_array = json_decode($message, true);
        // смотрим делйствительно ли у нас в эвенте содержится id маилбокса
        if(isset($message_array['data']['mailbox_id'])) {
            // смотрим по id маилбокса и собираем id всех онлайн коннектов
            $connection_ids_by_mailbox = [];
            foreach ($clients_ident_data as $connection_id => $client_ident_data){
                if($client_ident_data['mailbox_id'] === $message_array['data']['mailbox_id']){
                    $connection_ids_by_mailbox[] = $connection_id;
                }
            }

            if(!empty($connection_ids_by_mailbox)){
                // рассылаем событие всем маилбоксам кто онлайн
                foreach ($connection_ids_by_mailbox as $connection_id_by_mailbox){
                    fwrite($client_connects[$connection_id_by_mailbox], self::encode($message));
                }
            }
        }
    }

    // функция которая рассылает пакет всем всем пользователям онлайн в определенной структуре
    public static function send_to_structure_event($client_connects, $clients_ident_data, $message) : void
    {
        $message_array = json_decode($message, true);

        // проверяем, дейсвительно ли нам прислали пакет где указана структура
        if(isset($message_array['data']['structure_id'])){
            // смотрим по id маилбокса и собираем id всех онлайн коннектов
            $connection_ids_by_structure = [];
            foreach ($clients_ident_data as $connection_id => $client_ident_data){
                if($client_ident_data['structure_id'] === $message_array['data']['structure_id']){
                    $connection_ids_by_structure[] = $connection_id;
                }
            }

            if(!empty($connection_ids_by_structure)){
                // рассылаем событие всем пользователям онлайн кто кто находится в структуре
                foreach ($connection_ids_by_structure as $connection_id_by_structure){
                    fwrite($client_connects[$connection_id_by_structure], self::encode($message));
                }
            }
        }
    }

    // функция которая рассылает пакет всем всем пользователям онлайн в определенной структуре
    public static function send_to_user_event($client_connects, $clients_ident_data, $message) : void
    {
        $message_array = json_decode($message, true);
        // проверяем, дейсвительно ли нам прислали пакет где указана структура
        if(isset($message_array['data']['user_id'])){
            // смотрим по id маилбокса и собираем id всех онлайн коннектов
            foreach ($clients_ident_data as $connection_id => $client_ident_data){
                if($client_ident_data['user_id'] === $message_array['data']['user_id']){
                    $connection_id_by_user = $connection_id;
                }
            }

            if(isset($connection_id_by_user)){
                // посылаем сообщение пользователю с коннектом по id
                fwrite($client_connects[$connection_id_by_user], self::encode($message));
            }
        }
    }

    public static function encode($payload, $type = 'text', $masked = false)
    {
        // frame head это заголовки кодируемого пакета
        $frame_head = [];
        // пайлоад это тело кодируемого пакета
        $payload_length = strlen($payload);

        // кодируем исходящее соединение, при этом вместе с собщением мы можем отправить клиенту
        // в переменной $type мы можем указать что мы хотим сделать с соединением. отправить текст, закрыть соединение или пропинговать/запросить пинг
        switch ($type) {
            case 'text':
                // первый байт указывает на текстовый тип пакета (10000001):
                $frame_head[0] = 129;
                break;

            case 'close':
                // первый байт указывает на тип пакета указывающий закрытие соединения (10001000):
                $frame_head[0] = 136;
                break;

            case 'ping':
                // первый байт указывает на тип пакета осуществяющий пинг (10001001):
                $frame_head[0] = 137;
                break;

            case 'pong':
                // первый байт указывает на тип пакета осуществляющий понг байт после которого нас начнёт пинговать клиент (10001010):
                $frame_head[0] = 138;
                break;
        }

        // устанавливаем маску и длину тела пакета (используя 1, 3 или 9 байтов)
        if ($payload_length > 65535) {
            $payload_length_bin = str_split(sprintf('%064b', $payload_length), 8);
            $frame_head[1] = ($masked === true) ? 255 : 127;
            for ($increment = 0; $increment < 8; $increment++) {
                $frame_head[$increment + 2] = bindec($payload_length_bin[$increment]);
            }
            // обрабатываем заголовок content length и его первый должен быть нулем иначе выводим ошибку, что для кодирования нам прислали слишком большой пакет
            if ($frame_head[2] > 127) {
                return ['type' => '', 'payload' => '', 'error' => 'frame too large (1004)'];
            }
        } elseif ($payload_length > 125) {
            $payload_length_bin = str_split(sprintf('%016b', $payload_length), 8);
            $frame_head[1] = ($masked === true) ? 254 : 126;
            $frame_head[2] = bindec($payload_length_bin[0]);
            $frame_head[3] = bindec($payload_length_bin[1]);
        } else {
            $frame_head[1] = ($masked === true) ? $payload_length + 128 : $payload_length;
        }

        // конвертируем заголовки пакета в строку:
        foreach (array_keys($frame_head) as $increment) {
            $frame_head[$increment] = chr($frame_head[$increment]);
        }
        if ($masked === true) {
            // генерируем случайные 4 байта, для кодирования пакета которые будут идти между заголовком и телом пакета
            $mask = [];
            for ($increment = 0; $increment < 4; $increment++) {
                /** @noinspection all */
                $mask[$increment] = chr(random_int(0, 255));
            }

            $frame_head = array_merge($frame_head, $mask);
        }
        $frame = implode('', $frame_head);

        // объеденяем получившийся пакет заголовка с телом запроса переодически запихивая в него рандомные байты
        // рандомных байтов запихнется ровно столько, сколько у нас имеется символов в передаваемом сообщении
        for ($increment = 0; $increment < $payload_length; $increment++) {
            $frame .= ($masked === true) ? $payload[$increment] ^ $mask[$increment % 4] : $payload[$increment];
        }
        return $frame;
    }

    /** функция декодирования сообщений которые отправляем нам фронтенд или же наш бэкэнд евент
     * @param $data
     * @return array|bool
     */
    public static function decode($data)
    {
        $unmasked_payload = '';
        $decoded_data = [];

        // estimate frame type:
        $first_byte_binary = sprintf('%08b', ord($data[0]));
        $second_byte_binary = sprintf('%08b', ord($data[1]));
        $operation_code = bindec(substr($first_byte_binary, 4, 4));
        $is_masked = strpos($second_byte_binary, '1') === 0;
        $payload_length = ord($data[1]) & 127;

        // расшифрованное тело запроса, по первому байту определяем тип запроса и обрабатываем соответствующим образом:
        if (!$is_masked) {
            return array('type' => '', 'payload' => '', 'error' => 'protocol error (1002)');
        }

        switch ($operation_code) {
            // текстовый запрос:
            case 1:
                $decoded_data['type'] = 'text';
                break;

            // текстовый запрос но в бинарном формате
            case 2:
                $decoded_data['type'] = 'binary';
                break;

            // закрытие соединение:
            case 8:
                $decoded_data['type'] = 'close';
                break;

            // запрос пинга:
            case 9:
                $decoded_data['type'] = 'ping';
                break;

            // запрос пинга с обратной стороны:
            case 10:
                $decoded_data['type'] = 'pong';
                break;

            default:
                return array('type' => '', 'payload' => '', 'error' => 'unknown operation_code (1003)');
        }

        if ($payload_length === 126) {
            $mask = substr($data, 4, 4);
            $payload_offset = 8;
            $data_length = bindec(sprintf('%08b', ord($data[2])) . sprintf('%08b', ord($data[3]))) + $payload_offset;
        } elseif ($payload_length === 127) {
            $mask = substr($data, 10, 4);
            $payload_offset = 14;
            $tmp = '';
            for ($i = 0; $i < 8; $i++) {
                $tmp .= sprintf('%08b', ord($data[$i + 2]));
            }
            $data_length = bindec($tmp) + $payload_offset;
            unset($tmp);
        } else {
            $mask = substr($data, 2, 4);
            $payload_offset = 6;
            $data_length = $payload_length + $payload_offset;
        }

        /**
         * We have to check for large frames here. socket_recv cuts at 1024 bytes
         * so if websocket-frame is > 1024 bytes we have to wait until whole
         * data is transfer.
         */
        if (strlen($data) < $data_length) {
            return false;
        }

        if ($is_masked) {
            for ($i = $payload_offset; $i < $data_length; $i++) {
                $j = $i - $payload_offset;
                if (isset($data[$i])) {
                    $unmasked_payload .= $data[$i] ^ $mask[$j % 4];
                }
            }
            $decoded_data['payload'] = $unmasked_payload;
        } else {
            $payload_offset -= 4;
            $decoded_data['payload'] = substr($data, $payload_offset);
        }

        return $decoded_data;
    }

    // handshake (рукопожатие) требуется для соединения вебсоккетов с фронтенда
    public static function handshake($client_connect)
    {
        $info = [];
        $line = fgets($client_connect);
        $header = explode(' ', $line);
        $info['method'] = $header[0];
        $info['uri'] = $header[1];

        //считываем заголовки из соединения
        while ($line = rtrim(fgets($client_connect))) {
            if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
                $info[$matches[1]] = $matches[2];
            } else {
                break;
            }
        }

        $address = explode(':', stream_socket_get_name($client_connect, true)); //получаем адрес клиента
        $info['ip'] = $address[0];
        $info['port'] = $address[1];

        if (empty($info['Sec-WebSocket-Key'])) {
            return false;
        }

        // отправляем заголовок согласно протоколу вебсокета
        $sec_web_socket_accept = base64_encode(pack('H*', sha1($info['Sec-WebSocket-Key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
        $upgrade = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" .
            "Upgrade: websocket\r\n" .
            "Connection: Upgrade\r\n" .
            "Sec-WebSocket-Accept:$sec_web_socket_accept\r\n\r\n";
        fwrite($client_connect, $upgrade);

        return $info;
    }

    // если есть access_token выведет его, иначе выведет false;
    public static function check_access_token($client_info){
        /** @noinspection all */
        if(isset($client_info['uri']) && preg_match('/\/\?access_token=(.*)/m', $client_info['uri'], $token_match) && isset($token_match[0], $token_match[1])) {
            unset($token_match[0]);
            $token_match = array_values($token_match);
            return $token_match[0];
        }
        return false;
    }

    public static function is_json($string): bool
    {
        json_decode($string, true);
        return (json_last_error() === JSON_ERROR_NONE);
    }

}
