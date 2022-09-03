:call plug#begin('~/.vim/autoload')
Plug 'morhetz/gruvbox'

Plug 'junegunn/goyo.vim'
call plug#end()

" Exiting vim and Goyo at the same time
function! s:goyo_enter()
  let b:quitting = 0
  let b:quitting_bang = 0
  autocmd QuitPre <buffer> let b:quitting = 1
  cabbrev <buffer> q! let b:quitting_bang = 1 <bar> q!
endfunction

function! s:goyo_leave()
  " Quit Vim if this is the only remaining buffer
  if b:quitting && len(filter(range(1, bufnr('$')), 'buflisted(v:val)')) == 1
    if b:quitting_bang
      qa!
    else
      qa
    endif
  endif
endfunction

autocmd! User GoyoEnter call <SID>goyo_enter()
autocmd! User GoyoLeave call <SID>goyo_leave()

filetype indent on

" Auto entering Goyo in linenumber
autocmd vimenter * Goyo 100
autocmd vimenter * set nu
autocmd vimenter * set rnu
autocmd vimenter * set tabstop=4
autocmd vimenter * set shiftwidth=4
autocmd vimenter * set ignorecase
autocmd vimenter * syntax on

" Switch to insert mode highlight
:autocmd InsertEnter,InsertLeave * set cul!

" Compilation shortcuts for C and python
autocmd vimenter * noremap <F8> : !gcc % && ./a.out <CR>
autocmd vimenter * noremap <F9> : !python3 % <CR>

" Some remapping to be more comfortable
autocmd vimenter * noremap <Space> j
autocmd vimenter * noremap j h
autocmd vimenter * inoremap ` <Esc>

" Choosing the colorscheme
autocmd vimenter * ++nested colorscheme gruvbox

" --------What you actually need to use vim-----------
" :x      --> Save and Quit
" :w      --> Just Save
" :![CMD] --> Execute the command [CMD]

" Go         --> insert at the end of file
" [number]Go --> insert at [number] line
" 1GO        --> insert at the top of file
" [number]G  --> Go to [number] line

" yy        --> Copy the current line
" dd        --> Cut the current line
" p / P     --> Paste text after/before cursor

