<?php /** @noinspection PhpUnused */
namespace App\Http\Controllers\API\wss;

use App\Http\Controllers\Controller;
use GuzzleHttp\Client;
use Exception;

/**
 * Автор класса Александр Хакимов  https://github.com/hackimov
 * Класс позволяет отправлять сообщения с backend части приложения eregister в сокет сервер
 * которые в дальнейшем будут распределяться всем подключенным клиентам по условиям логики написанной выше
 */

class ErgWebsocketStartDaemon extends Controller
{
    public static function websocket_daemon(): array
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
            $url = ErgWebsocketClientController::url();
            // все клиенты проходят идентификацию, соответственно так как мы тоже маскируемся под клиента у нас должен быть access token
            // он будет обрабатываться статично и возможно в дальнейшем браться из настроек
            $access_token = 'QkFDS19BQ0NFU1NfVE9LRU4=';
            /** *************************************************************************/

            $incoming_data = '{"ping":true}';
            connect:
            // необходимые заголовки отправляемые соккету для соединения
            $headers  = 'GET / HTTP/1.1'.$rn.
                'Upgrade: WebSocket'.$rn.
                'Connection: Upgrade'.$rn.
                'uri: /?access_token='.$access_token.$rn.
                "Origin: $url".$rn.
                "Host: $host".$rn.
                'Sec-WebSocket-Key: DAEMON_WEBSOCKET_'.ErgWebsocketClientController::random_key().$rn.
                'Content-Length: '.strlen($incoming_data).$rn.$rn;
            // WebSocket handshake (рукопожатие, имитация фронтенда)
            $backend_socket_connect = fsockopen($host, $port, $error_number, $error_string, 2);
            fwrite($backend_socket_connect, $headers);
            $decoded_response = ErgWebsocketClientController::response_decoder(fread($backend_socket_connect, 2000));

            if($decoded_response['content'] === false ){
                // если у нас не получилось соединиться с сокет сервером пытаемся это делать до тех пор пока это у нас не получится
                goto connect;
            }
            fclose($backend_socket_connect);
        } catch (Exception $exception){
            // пытаемся запустить соккет сервер
            try{
                $guzzle = new Client(['verify' => false]);
                $guzzle->get( $url. '/api/websocket/websocket_start', ['timeout'  => 1]);
            } catch (Exception $ex){
                return ['message' => ' websocket started'];
            }
        }
        return $decoded_response;
    }
}
