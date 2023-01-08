package ru.kata.spring.boot_security.demo.service;




import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;
public interface UserService {
    List<User> listUsers();
    User getUser(int id);
    void edit(int id, User user);
    void add(User user);

    void delete(int id);

}
