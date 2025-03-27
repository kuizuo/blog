---
slug: hortiControle
title: Sistema Java + Angular
date: 2022-07-08
authors: Eliziane
tags: [angular, java]
keywords: [angular, java]
---
<!-- truncate -->

[JS deobfuscator](http://js-deobfuscator.kuizuo.cn/)


## Sistema HortiControle

Olá, pessoal! Hoje eu quero compartilhar um projeto que foi um verdadeiro desafio – e aprendizado – durante o meu estágio obrigatório na UniFil no ano de 2024. Desenvolvi o HortiControle, um sistema completo para gerenciar uma empresa de hortifrutigranjeiros. A ideia era automatizar processos que antes eram feitos manualmente.

## Tecnologias Usadas
Utilizei:
- **Java** e **Spring Boot** para a lógica do backend;
- **Angular** para criar uma interface moderna e responsiva;
- **PostgreSQL** para gerenciar os dados de forma robusta.

## Telas do sistema

A seguir, veja um resumo de cada tela do sistema, mostrando o que cada uma faz de maneira clara e objetiva:

### Tela de Login
Formulário simples para entrada do e-mail e senha, com opção para recuperação de senha.
Objetivo: Autenticar o usuário e garantir acesso seguro. 🔐
![Meu Projeto](/img/project/login.png "Projeto")

### Tela de Dashboard (Início)
Apresenta o menu lateral com atalhos para as demais funcionalidades e exibe um resumo dos dados do sistema.
Objetivo: Facilitar a navegação e fornecer uma visão geral do sistema. 🚀

### Tela da Conta do Usuário
Exibe as informações pessoais com opções para editar dados e alterar a senha.
Objetivo: Permitir a gestão dos dados do usuário de forma prática. 👤

### Tela de Cálculo de Estimativas
Interface para selecionar o produto e inserir a quantidade, retornando a estimativa de produção de bandejas.
Objetivo: Auxiliar no planejamento da produção de forma automatizada. 📊

### Tela de Histórico de Cálculo
Lista os cálculos de produção realizados anteriormente, permitindo consulta rápida.
Objetivo: Manter um registro acessível das estimativas passadas. 🕒

### Tela de Lista de Produção
Exibe todas as produções registradas, com ferramentas para busca, edição e exclusão.
Objetivo: Controlar e acompanhar as produções realizadas. 🏭

### Tela de Cadastro/Edição de Produção
Formulário para adicionar ou modificar informações de uma produção (nome, quantidade, data).
Objetivo: Facilitar a atualização dos registros de produção. ✍️

### Tela de Fornecedores
Mostra a lista de fornecedores cadastrados, com opção de busca e exclusão.
Objetivo: Gerenciar os dados dos fornecedores da empresa. 🤝

### Tela de Cadastro/Edição de Fornecedor
Formulário para inserir ou editar dados do fornecedor (nome, telefone, e-mail, CNPJ).
Objetivo: Manter os cadastros de fornecedores atualizados. 📝

### Tela de Produtos
Lista os produtos com informações como código, nome, peso, valor, quantidade ideal e por caixa.
Objetivo: Oferecer uma visão completa do portfólio de produtos. 📦

### Tela de Cadastro/Edição de Produto
Formulário para adicionar ou modificar os detalhes dos produtos.
Objetivo: Atualizar ou incluir novos produtos no sistema. ✨

### Tela de Vendas
Exibe as vendas realizadas, organizadas por produto, valor e status de pagamento.
Objetivo: Monitorar as transações de vendas de forma organizada. 💰

### Tela de Cadastro/Edição de Vendas
Formulário para registrar ou alterar informações de uma venda, incluindo quantidade e valor unitário.
Objetivo: Garantir o registro correto das operações de venda. 🛒

### Tela de Compra
Lista as compras e insumos recebidos, detalhando fornecedor, quantidade, valor e data.
Objetivo: Controlar as aquisições da empresa de forma eficaz. 🛍️

### Tela de Cadastro/Edição de Compra
Formulário para adicionar ou editar registros de compras.
Objetivo: Facilitar o gerenciamento das entradas de insumos. 📥

### Tela de Despesas
Exibe as despesas com informações de fornecedor, descrição, valor e data de vencimento.
Objetivo: Monitorar os gastos e o fluxo financeiro da empresa. 💸

### Tela de Cadastro/Edição de Despesas
Formulário para incluir ou alterar despesas.
Objetivo: Manter o controle dos custos atualizado. 🧾

### Tela de Estoque
Mostra os produtos em estoque, com detalhes sobre quantidades, data da última entrada e valores.
Objetivo: Acompanhar a disponibilidade e gerenciar o inventário. 📊

### Tela de Faturamento
Permite consultar o faturamento mensal, com filtros de data para visualizar os resultados.
Objetivo: Analisar o desempenho financeiro da empresa em períodos específicos. 📈

### Tela de Lista de Faturamento
Exibe uma listagem detalhada dos dados de faturamento, consolidando as informações financeiras.
Objetivo: Auxiliar na tomada de decisão através de uma visão completa dos resultados. 💼
