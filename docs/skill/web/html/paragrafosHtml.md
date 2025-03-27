---
id: parágrafos-símbolos
slug: /paragrafos-simbolos
title: Parágrafos/Quebras e Símbolos em HTML
date: 13-03-2025
authors: Eliziane
tags: [HTML, Parágrafos, Símbolos, Emojis]
keywords: [HTML, Parágrafos, Símbolos, Emojis, Programação, Web]
---

- **Parágrafos e Quebras**
    
    Ao escrever um parágrafo `<p></p>` em um arquivo HTML, é preciso observar:
    
    - Qualquer texto pode ser escrito de forma corrida e sem quebra de linha, desde que esteja entre o par de tags `<p></p>`.
    - Se houver a necessidade de quebrar o texto em determinado local, basta utilizar a tag `<br>`.
    - Se houver a necessidade de um espaço maior **NÃO UTILIZAR** várias tags `<br> <br> <br>`.
    - Se houver a necessidade de escrever as tags no texto, utiliza-se: `&lt;` = **Less than** e `&gt;` = **Greater than**.
    1. `&lt;p&gt;` para a tag `<p>`.
    2. `&lt;/p&gt;` para a tag `</p>`.
    3. `&lt;br&gt;` para `<br>`.
    
    ### Exemplo de código
    
    ```html
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Parágrafos</title>
    </head>
    <body>
        <h1>Parágrafos e quebras de linhas</h1>
        <hr>
        <p>Você pode escrever um parágrafo de
        qualquer jeito.
        Basta colocar tudo no meio do par
        te tags &lt;p&gt; e &lt;/p&gt;
        </p>
        <p>Se precisar quebrar
            o texto em algum lugar
            específico <br> como esse
            Você pode usar a tag &lt;br&gt;.
        </p>
    </body>
    </html>
    ```

- **Símbolos e Emoji**
    
    Abaixo estão alguns exemplos de símbolos:
    
    ```html
    <p>Vamos adicionar alguns símbolos especiais:
            &reg;
            &copy;
            &trade;
            &euro;
            &pound;
            &cent;
            &Delta;
            &uparrow;
            &uarr;
        </p>
    ```
    
    Para adicionar um emoji, basta buscar pelo seu código em sites como o [Emojipedia](https://emojipedia.org/) e colocar o seguinte comando antes do código do emoji: `&#x`.
    
    ### Exemplo de código:
    
    ```html
    <p>Vamos adicionar alguns emojis:
            &#x1F60A
            &#x1F680
        </p>
    ```

-- Aula do curso do Gustavo Guanabara
