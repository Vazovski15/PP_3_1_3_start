package ru.kata.spring.boot_security.demo.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepository;


import java.util.List;
@Service
public class UserServiceImpl implements UserService{


    private final UserRepository userRepository;

    private final RoleServiceImpl roleService;

    public UserServiceImpl(UserRepository userRepository, RoleServiceImpl roleService) {
        this.userRepository = userRepository;
        this.roleService = roleService;
    }


    @Override
    @Transactional
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    @Transactional
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    @Override
    @Transactional
    public void saveUser(User user) {
        userRepository.save(user);

    }

    @Override
    @Transactional
    public User findByIdUsers(Long id) {
        return userRepository.findById(id).orElseThrow(()->new RuntimeException("Пользователь не найден") );
    }

    @Override
    @Transactional
    public void updateUser(Long id, User user) {
        User userFromDb=findByIdUsers(id);
        userFromDb.setUsername(user.getUsername());
        userFromDb.setPassword(user.getPassword());
        userRepository.save(userFromDb);

    }

    @Override
    @Transactional
    public void deleteByIdUsers(Long id) {
        userRepository.deleteById(id);

    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username);
        if(user == null) {
            throw new UsernameNotFoundException(String.format("User '%s' not found", username));
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                roleService.mapRolesToAuthorities(user.getRoles()));
    }

    }

