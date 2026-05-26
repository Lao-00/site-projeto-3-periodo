# Acessibilidade Implementada no Projeto (Baseado no Guia WCAG 2.1 AA)

## 1. Contraste (WCAG 1.4.3)

- Texto normal: Contraste mínimo de 4.5:1 (ex: #1a1a1a sobre #f5f5f5).
- Texto grande e botões primários: Contraste mínimo de 3:1.

## 2. Navegação por Teclado (WCAG 2.1.1)

- Todos os elementos interativos são acessíveis sequencialmente via `Tab`.
- Ordem de navegação estruturada de forma lógica (esquerda para direita, cima para baixo).
- Presença de _Skip link_ no topo para atalho direto ao conteúdo principal.
- Suporte às teclas `Enter` e `Space` em links, botões e controles de formulário.

## 3. Foco Visível (WCAG 2.4.7)

- Aplicação de `outline: 3px solid var(--accent)` e `outline-offset: 2px` em todos os elementos em estado de `:focus`.
- Cor de contorno com contraste adequado (ouro).

## 4. Textos Alternativos (WCAG 1.1.1)

- Imagens informativas possuem atributo `alt` com descrições detalhadas.
- Imagens decorativas e ícones visuais utilizam `alt=""` ou `aria-hidden="true"`.

## 5. Estrutura Semântica e Hierarquia (WCAG 1.3.1)

- Uso de blocos estruturais HTML5 (`<header>`, `<main>`, `<footer>`, `<section>`, `<nav>`).
- Uso restrito a apenas um `<h1>` por página.
- Progressão de títulos sequencial e sem saltos de níveis (`h1` → `h2` → `h3`).
- Formulários agrupados contextualmente utilizando `<fieldset>` e `<legend>`.

## 6. Atributos ARIA (WCAG 1.3.1 / 4.1.2)

- `aria-label`: Aplicado em botões e seções sem rótulo visível em texto.
- `aria-labelledby` e `aria-describedby`: Relacionamento de componentes com descrições e instruções (ex: formulários).
- `role`: Definição de papel semântico para marcações chave.
- `aria-live`: Utilizado para ditar mudanças dinâmicas na interface para softwares de leitura.

## 7. Formulários e Rótulos (WCAG 3.3.2)

- Todos os `<input>`, `<select>` e `<textarea>` são pareados explicitamente com a tag `<label>` via atributo `for`.
- Indicação técnica e visual para campos de preenchimento obrigatório.
- Hitboxes de toque (touch targets) com altura mínima de 44px.

## 8. Legibilidade e Responsividade (WCAG 1.4.10)

- Tipografia base sem serifa com tamanho root de 16px.
- Suporte a ampliação (zoom) de até 200% sem perda de conteúdo.
- Adaptação fluida do layout (reflow) para telas de 320px (Mobile) a 1920px (Desktop) sem necessidade de rolagem horizontal transversal ao conteúdo de leitura.
