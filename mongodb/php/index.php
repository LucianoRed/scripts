<?php

require 'vendor/autoload.php';

try {

    $client = new MongoDB\Client("mongodb://mongodb-standalone:27017");

    $collection = $client->testdb->teste;

    // insere um registro
    $collection->insertOne([
        'mensagem' => 'MongoDB funcionando!',
        'data' => date('Y-m-d H:i:s')
    ]);

    echo "<h2>Registro inserido com sucesso!</h2>";

    echo "<h3>Dados no banco:</h3>";

    $cursor = $collection->find();

    foreach ($cursor as $doc) {
        echo $doc['mensagem'] . " - " . $doc['data'] . "<br>";
    }

} catch (Exception $e) {
    echo "Erro: " . $e->getMessage();
}
