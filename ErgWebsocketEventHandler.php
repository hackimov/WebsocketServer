<?php /** @noinspection PhpUnused */

namespace App\Http\Controllers\API\wss;

use App\Http\Controllers\Controller;
use Illuminate\http\Request;

class ErgWebsocketEventHandler extends Controller
{
    public static function new_event(Request $request):array
    {
        $event = $request->getContent();
        return ErgWebsocketClientController::send_to_clients($event);
    }
}
