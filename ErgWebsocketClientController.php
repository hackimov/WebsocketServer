<?php /** @noinspection PhpUnused */
namespace App\Http\Controllers\API\wss;

use App\Http\Controllers\Controller;
use Exception;

/**
 * Автор класса Александр Хакимов  https://github.com/hackimov
 * Класс позволяет отправлять сообщения с backend части приложения eregister в сокет сервер
 * которые в дальнейшем будут распределяться всем подключенным клиентам по условиям логики написанной выше
 */

class ErgWebsocketClientController extends  Controller
{
    public static function send_to_clients($incoming_data):array
    {
        try{
            /** предопределенные настройки , которые будут работать с нашим вебсоккетом */
            // перенос строки \r\n
            $rn = "\r\n";
            //адрес вебсокет сервера к которому мы будем подключаться при срабатывании событий
            $host  = $_SERVER['SERVER_ADDR'];
            // порт вебсоккет сервера
            $port  = 7746;
            //url сервера уведомлений (текущего скрипта), где он был запущен
            $url = self::url();
            // все клиенты проходят идентификацию, соответственно так как мы тоже маскируемся под клиента у нас должен быть access token
            // он будет обрабатываться статично и возможно в дальнейшем браться из настроек
            $access_token = 'QkFDS19BQ0NFU1NfVE9LRU4=';
            /** *************************************************************************/
            connect:
            // необходимые заголовки отправляемые соккету для соединения
            $headers  = 'GET / HTTP/1.1'.$rn.
                'Upgrade: WebSocket'.$rn.
                'Connection: Upgrade'.$rn.
                'uri: /?access_token='.$access_token.$rn.
                "Origin: $url".$rn.
                "Host: $host".$rn.
                'Sec-WebSocket-Key: BACKEND_WEBSOCKET_'.self::random_key().$rn.
                'Content-Length: '.strlen($incoming_data).$rn.$rn;
            // WebSocket handshake (рукопожатие, имитация фронтенда)
            $backend_socket_connect = fsockopen($host, $port, $error_number, $error_string, 2);
            fwrite($backend_socket_connect, $headers);

            $decoded_response = self::response_decoder(fread($backend_socket_connect, 2000));

            if($decoded_response['content'] === false){
                // если у нас не получилось соединиться с сокет сервером пытаемся это делать до тех пор пока это у нас не получится
                goto connect;
            }

            fwrite($backend_socket_connect, $incoming_data);
            fclose($backend_socket_connect);
        } catch (Exception $exception){
            return ['success' => false];
        }
        return $decoded_response;
    }

    public static function url() : string
    {
        $server_name = $_SERVER['SERVER_NAME'];
        if (!empty($_SERVER['HTTPS']) && (strtolower($_SERVER['HTTPS']) === 'on' || $_SERVER['HTTPS'] === '1')) {
            $protocol = 'https';
        } else {
            $protocol = 'http';
        }
        return $protocol.'://'.$server_name;
    }

    /**
     * самый простой декодер убирающий в начале строки лишних байта
     * т.к. бэкэндом мы будем общаться без дополнительного шифрования
     * @param $incoming_data
     * @return array
     */
    public static function response_decoder($incoming_data): array
    {

        // тут разделяем наши данные от заголовков
        $pocket_data     = explode("\r\n\r\n", $incoming_data);
        $headers         = explode("\r\n", $pocket_data[0]);
        // удаляем 2 байта
        $pocket_content  = mb_strcut($pocket_data[1], 2);
        $data = [];
        $data['headers'] = $headers;
        $data['content'] = $pocket_content;
        return $data;
    }

    public static function random_key($length = 5) {
        return substr(str_shuffle(str_repeat($x='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
    }


}
