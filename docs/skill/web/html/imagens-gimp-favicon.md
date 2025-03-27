---
id: imagens-gimp-favicon
slug: /imagens-gimp-favicon
title: Imagens/GIMP/Favicon
date: 2022-05-09
authors: Eliziane
tags: [HTML, Imagens, GIMP, Favicon]
keywords: [Imagens, GIMP, Favicon, Web, Programação]
---

**Formatos de Imagens:** Utilizar o GIMP, software de tratamento de imagens gratuito e open source, para alterar largura, altura e resolução de imagens, de modo a transformar arquivo em algo menor, ocupando assim uma quantidade de espaço menor e consequentemente possibilitando o desenvolvimento de um site que não ocupe muito espaço.

**Adicionar Imagens ao Site:**

Podemos adicionar imagens ao site com o seguinte código: `<img src="caminho, nome ou link" alt="descrição da imagen">`

**Exemplo com o código da aula:**

```

<body>

    <h1>Testando carga e imagens</h1>

    <p>Abaixo você vai ver uma imagem</p>

    <img src="logohtml.png" alt="Logo html5">

    <p>Podemos carregar imagens que estão em subpastas:</p>

    <img src="imagens/css.png" alt="Logo css">

    <p>Podemos carregar imagens externas:</p>

    <img src="https://bognarjunior.files.wordpress.com/2018/01/1crcyaithv7aiqh1z93v99q.png" alt="Logo javascript">

</body>

```

É possível adicionar imagens ao site adicionando o arquivo .png na pasta onde está localizado o arquivo .html, em seguida digitamos ''img'' e pressionamos a tecla enter (o código é gerado automaticamente).

-   obs.: basta posicionar o cursor entre as aspas após "src" e apertar a tecla "ctrl + espaço", os arquivos irão aparecer para o o preenchimento automático.

Podemos preencher com:

-   Nome do arquivo se ele estiver na mesma pasta;

-   Caminho + nome do arquivo se ele estiver em uma subpasta;

-   Url da imagem que está na web, lembrando que se o servidor onde está a imagem cair a imagem do nosso site também pode cair.

**Favicon de um Site:**

Para adicionar um Favicon ao nosso site primeiro devemos baixar ou transformar algo em um arquivo "ICO", para baixar ícones basta utilizar o site [https://www.iconarchive.com/](https://www.iconarchive.com/) e para criar, utilize o site [Favicon.io](https://favicon.io/).

O ícone pode ser adicionado ao site com o seguinte código acima do title:

```

<link rel="shortcut icon" href="Dolphin.ico" type="image/x-icon">

    <title>Teste favicon</title>

```

Obs.: substituir pelo nome do arquivo a ser utilizado `href="Dolphin.ico"` .

--Aula do canal do Gustavo Guanabara